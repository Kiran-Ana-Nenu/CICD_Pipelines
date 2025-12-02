import groovy.json.JsonSlurper

pipeline {
  agent any

  parameters {
    string(name: 'GIT_REF', defaultValue: 'release/1.0', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build','warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
    booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable debug logs (set -x, print env, system info)')
  }

 environment {
    // 👇 Provided from Jenkins global env or job env
    // GIT_URL        = "https://github.com/Kiran-Ana-Nenu/Springboot_App.git"
    GIT_URL        = "https://github.com/Kiran-Ana-Nenu/ssl_monitoring.git"
    DOCKER_HUB_URL = "https://index.docker.io/v1/"
    DOCKER_REPO    = "kiranpayyavuala/sslexpire_application"
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

    stage('Validate Git Ref + Set Image Tags') {
      steps {
        script {
          def ref = params.GIT_REF.trim()
          if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
            error "Invalid ref '${ref}'. Allowed only: v* tags or release* branches."
          }

          env.IMAGE_TAG = ref.replaceAll('/', '-')

          // build a hashmap for later use
          env.IMAGES = [
            "web"        : "${env.DOCKER_REPO_PREFIX}-web:${env.IMAGE_TAG}",
            "worker-app" : "${env.DOCKER_REPO_PREFIX}-worker-app:${env.IMAGE_TAG}",
            "worker-mail": "${env.DOCKER_REPO_PREFIX}-worker-mail:${env.IMAGE_TAG}",
            "nginx"      : "${env.DOCKER_REPO_PREFIX}-nginx:${env.IMAGE_TAG}"
          ] as groovy.json.JsonOutput

          echo "IMAGE_TAG = ${env.IMAGE_TAG}"
          echo "Images will be:"
          readJSON text: env.IMAGES).each { k, v -> echo " - ${k}: ${v}" }
        }
      }
    }

    stage('Checkout Source Code') {
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

    stage('Build Docker Images (no cache)') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")

          // Dockerfile map
          def dockerfiles = [
            "web"        : "docker/app.Dockerfile",
            "worker-app" : "docker/app.Dockerfile",
            "worker-mail": "docker/mail.Dockerfile",
            "nginx"      : "docker/nginx.Dockerfile"
          ]

          def images = readJSON text: env.IMAGES
          images.each { name, fullImage ->
            echo "🐳 Building → ${fullImage}"
            sh """
              docker build \
                --no-cache \
                --build-arg GIT_REF=${params.GIT_REF} \
                --build-arg APP_VERSION=${env.IMAGE_TAG} \
                -f ${dockerfiles[name]} \
                -t ${fullImage} .
            """
          }
        }
      }
    }

    stage('Trivy Scan (JSON)') {
      steps {
        script {
          def images = readJSON text: env.IMAGES
          images.each { name, fullImage ->
            echo "🔍 Scanning ${fullImage}"
            sh "trivy image --format json --exit-code 1 --severity HIGH,CRITICAL ${fullImage} -o trivy-${name}.json || true"
            archiveArtifacts artifacts: "trivy-${name}.json", allowEmptyArchive: true

            def json = new JsonSlurper().parseText(readFile("trivy-${name}.json"))
            def vulnCount = 0
            json.Results.each { r ->
              if (r.Vulnerabilities) vulnCount += r.Vulnerabilities.size()
            }
            echo "⚠ Vulnerabilities in ${name}: ${vulnCount}"

            if (vulnCount > 0 && params.TRIVY_FAIL_ACTION == "fail-build")
              error "❌ Trivy failed for ${name} — ${vulnCount} HIGH/CRITICAL"
            else if (vulnCount > 0)
              currentBuild.result = "UNSTABLE"
          }
        }
      }
    }

    stage('Push Docker Images') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")
          withCredentials([usernamePassword(credentialsId: env.DOCKER_CREDENTIALS_ID, usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            sh "echo '${PASS}' | docker login ${DOCKER_HUB_URL} -u '${USER}' --password-stdin"
            def images = readJSON text: env.IMAGES
            images.each { name, fullImage ->
              echo "⬆️ Pushing ${fullImage}"
              sh "docker push ${fullImage}"
            }
            sh "docker logout"
          }
        }
      }
    }
  }

  post {
    always {
      echo "🔁 Pipeline Finished — Status: ${currentBuild.result ?: 'SUCCESS'}"
    }
    success {
      echo "🎉 SUCCESS — All 4 images pushed with tag ${env.IMAGE_TAG}"
    }
    unstable {
      echo "⚠ UNSTABLE — Images pushed but Trivy reported vulnerabilities"
    }
    failure {
      echo "❌ FAILED — Check logs"
    }
  }
}
