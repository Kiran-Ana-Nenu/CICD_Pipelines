import groovy.json.JsonSlurper
import groovy.json.JsonOutput

pipeline {
  agent any

  parameters {
    string(name: 'GIT_REF', defaultValue: 'release/1.0', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build', 'warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
    booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable debug logs (set -x, print env, system info)')
  }


 environment {
    // 👇 Provided from Jenkins global env or job env
    // GIT_URL            = "https://github.com/Kiran-Ana-Nenu/Springboot_App.git"
    GIT_URL               = "https://github.com/Kiran-Ana-Nenu/ssl_monitoring.git"
    DOCKER_HUB_URL        = "https://index.docker.io/v1/"
    DOCKER_REPO_PREFIX    = "kiranpayyavuala/sslexpire_application"
    DOCKER_CREDENTIALS_ID = "dockerhub-creds"
  }
  stages {

    stage('Clean Workspace (Pre-build)') {
      when { expression { params.CLEAN_BEFORE } }
      steps {
        echo "🧹 Cleaning workspace before build..."
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

          def images = [
            "web"        : "${env.DOCKER_REPO_PREFIX}-web:${env.IMAGE_TAG}",
            "worker-app" : "${env.DOCKER_REPO_PREFIX}-worker-app:${env.IMAGE_TAG}",
            "worker-mail": "${env.DOCKER_REPO_PREFIX}-worker-mail:${env.IMAGE_TAG}",
            "nginx"      : "${env.DOCKER_REPO_PREFIX}-nginx:${env.IMAGE_TAG}"
          ]

          env.IMAGES = JsonOutput.toJson(images)

          echo "IMAGE_TAG = ${env.IMAGE_TAG}"
          echo "📦 Docker images to build:"
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

    stage('Docker Build (no cache)') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")

          def images = readJSON(text: env.IMAGES)
          images.each { name, image ->
            echo "🔨 Building: ${name} -> ${image}"
            sh """
              docker build \
                --no-cache \
                --build-arg APP_ROLE=${name} \
                --build-arg APP_VERSION=${env.IMAGE_TAG} \
                -t ${image} .
            """
          }
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
      steps {
        script {
          withCredentials([usernamePassword(credentialsId: env.DOCKER_CREDENTIALS_ID, usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            sh """
              echo "${PASS}" | docker login ${DOCKER_HUB_URL} -u "${USER}" --password-stdin
            """

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
      echo "🎉 SUCCESS — All Docker images pushed successfully"
    }
    unstable {
      echo "⚠ UNSTABLE — Images pushed but Trivy found vulnerabilities"
    }
    failure {
      echo "❌ FAILED — see above logs"
    }
  }
}
