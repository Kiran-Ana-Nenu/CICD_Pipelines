import groovy.json.JsonSlurper
import groovy.json.JsonOutput

pipeline {
  agent any

  parameters {
    string(name: 'GIT_REF', defaultValue: 'release/1.8', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build', 'warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
    booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable debug logs (set -x, print env, system info)')

    // MULTI-select checkbox for images
    extendedChoice(
        name: 'BUILD_IMAGES',
        type: 'PT_CHECKBOX',
        value: 'web,worker-app,worker-mail,nginx',
        description: 'Select which images to build'
    )

    booleanParam(name: 'USE_CACHE', defaultValue: true, description: 'Enable Docker build cache')
    booleanParam(name: 'PUSH_IMAGES', defaultValue: true, description: 'Push built images to Docker Hub')
  }

  environment {
    GIT_URL               = "https://github.com/Kiran-Ana-Nenu/ssl_monitoring.git"
    DOCKER_HUB_URL        = "https://index.docker.io/v1/"
    DOCKER_REPO_PREFIX    = "kiranpayyavuala/sslexpire_application"
    DOCKER_CREDENTIALS_ID = "dockerhub-creds"
  }

  stages {

    stage('Clean Workspace (Pre-build)') {
      when { expression { params.CLEAN_BEFORE } }
      steps {
        echo "🧹 Cleaning workspace..."
        cleanWs()
      }
    }

    stage('Validate Git Ref + Generate Image Tags') {
      steps {
        script {
          def ref = params.GIT_REF.trim()
          if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
            error "❌ Invalid ref '${ref}'. Allowed only: v* tags or release* branches."
          }

          env.IMAGE_TAG = ref.replaceAll("/", "-")

          // Define all images
          def allImages = [
            "web"        : "${env.DOCKER_REPO_PREFIX}-web:${env.IMAGE_TAG}",
            "worker-app" : "${env.DOCKER_REPO_PREFIX}-worker-app:${env.IMAGE_TAG}",
            "worker-mail": "${env.DOCKER_REPO_PREFIX}-worker-mail:${env.IMAGE_TAG}",
            "nginx"      : "${env.DOCKER_REPO_PREFIX}-nginx:${env.IMAGE_TAG}"
          ]

          // Filter based on selected images
          def selectedImages = [:]
          params.BUILD_IMAGES.split(",").each { img ->
            if (allImages.containsKey(img)) selectedImages[img] = allImages[img]
          }

          env.IMAGES = JsonOutput.toJson(selectedImages)
          echo "IMAGE_TAG = ${env.IMAGE_TAG}"
          echo "📦 Selected Docker images to build:"
          readJSON(text: env.IMAGES).each { k, v -> echo " - ${k}: ${v}" }
        }
      }
    }

    stage('Checkout Code') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")
          checkout([$class: 'GitSCM',
              branches: [[name: params.GIT_REF]],
              userRemoteConfigs: [[url: env.GIT_URL]]
          ])
        }
      }
    }
stage('Admin Approval') {
    steps {
        script {
            // Build a multiline message with current job parameters
            def paramText = params.collect { k, v -> "${k} = ${v}" }.join("\n")
            
            // Show input dialog with job parameters
            def user = input(
                message: """Admin approval required to continue workspace cleanup.

📌 Job Parameters:
${paramText}""",
                ok: 'Approve',
                submitter: env.APPROVERS
            )
            
            echo "✅ Approved by: ${user}"
        }
    }
}

// stage('Docker Build (Parallel)') {
//   steps {
//     script {
//       def images = readJSON(text: env.IMAGES)
//       def buildTasks = [:]
//       def dockerPath = "docker/"

//       images.each { name, image ->
//         buildTasks["Build ${name}"] = {
//           script {
//             def dockerFile = ""
//             // Assign Dockerfile based on image name
//             switch (name) {
//               case "web":
//               case "worker-app":
//                 dockerFile = "app.Dockerfile"
//                 break
//               case "worker-mail":
//                 dockerFile = "mail.Dockerfile"
//                 break
//               case "nginx":
//                 dockerFile = "nginx.Dockerfile"
//                 break
//               default:
//                 error("❌ Unknown image: ${name}")
//             }

//             echo "🔨 Building ${name} -> ${image} using ${dockerFile}"
//             sh """
//               docker build \
//                 ${params.USE_CACHE ? "" : "--no-cache"} \
//                 -f ${dockerPath}/${dockerFile} \
//                 --build-arg APP_ROLE=${name} \
//                 --build-arg APP_VERSION=${env.IMAGE_TAG} \
//                 -t ${image} ${dockerPath}
//             """
//           }
//         }
//       }

//       parallel buildTasks
//     }
//   }
// }

stage('Docker Build (Parallel)') {
  steps {
    script {
      def images = readJSON(text: env.IMAGES)
      def buildTasks = [:]
      def dockerPath = "docker"

      images.each { name, image ->
        buildTasks["Build ${name}"] = {
          script {
            def dockerFile = ""
            switch (name) {
              case "web":
              case "worker-app": dockerFile = "app.Dockerfile"; break
              case "worker-mail": dockerFile = "mail.Dockerfile"; break
              case "nginx": dockerFile = "nginx.Dockerfile"; break
              default: error("❌ Unknown image: ${name}")
            }

            echo "🔨 Building ${name} -> ${image} using ${dockerFile}"
            sh """
              docker build \
                ${params.USE_CACHE ? "" : "--no-cache"} \
                -f ${dockerPath}/${dockerFile} \
                --build-arg APP_ROLE=${name} \
                --build-arg APP_VERSION=${env.IMAGE_TAG} \
                -t ${image} .
            """
          }
        }
      }
      parallel buildTasks
    }
  }
}

    stage('Trivy Scan') {
      steps {
        script {
          def images = readJSON(text: env.IMAGES)
          images.each { name, image ->
            echo "🔍 Trivy scanning ${image}"
            sh "trivy image --format json --exit-code 1 --severity HIGH,CRITICAL ${image} -o trivy-${name}.json || true"
            archiveArtifacts artifacts: "trivy-${name}.json", allowEmptyArchive: true

            def jsonText = readFile("trivy-${name}.json")
            def json = new JsonSlurper().parseText(jsonText)
            def total = 0
            json.Results?.each { r -> total += r.Vulnerabilities?.size() ?: 0 }

            echo "⚠ HIGH/CRITICAL count for ${name}: ${total}"
            if (total > 0 && params.TRIVY_FAIL_ACTION == 'fail-build') {
              error "❌ Vulnerabilities found in ${name} — failing build"
            } else if (total > 0) {
              currentBuild.result = 'UNSTABLE'
              echo "⚠ Vulnerabilities found — marking UNSTABLE"
            } else {
              echo "✅ No HIGH/CRITICAL vulnerabilities"
            }
          }
        }
      }
    }

    stage('Push Images to Docker Hub') {
      when { expression { params.PUSH_IMAGES } }
      steps {
        script {
          withCredentials([usernamePassword(credentialsId: env.DOCKER_CREDENTIALS_ID, usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            sh "echo ${PASS} | docker login ${DOCKER_HUB_URL} -u ${USER} --password-stdin"

            def images = readJSON(text: env.IMAGES)
            images.each { name, image ->
              echo "📤 Pushing ${image}"
              sh "docker push ${image}"
            }

            sh "docker logout"
          }
        }
      }
    }
  }

  post {
    always {
      echo "🔁 Pipeline completed — Status: ${currentBuild.result ?: 'SUCCESS'}"
    }
    success {
      echo "🎉 SUCCESS — Selected Docker images pushed successfully"
    }
    unstable {
      echo "⚠ UNSTABLE — Images pushed but Trivy found vulnerabilities"
    }
    failure {
      echo "❌ FAILED — see logs"
    }
  }
}