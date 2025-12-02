import groovy.json.JsonSlurper

pipeline {
  agent any

  parameters {
    string(name: 'GIT_REF', defaultValue: 'release/1.0', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
    booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable verbose build logs')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build','warn-only'], description: 'Fail or warn on HIGH/CRITICAL vulnerabilities')
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

    stage('Clean Workspace (Optional)') {
      when { expression { params.CLEAN_BEFORE } }
      steps {
        echo "🧹 Cleaning workspace..."
        cleanWs()
      }
    }

    stage('Validate Git Ref') {
      steps {
        script {
          def ref = params.GIT_REF.trim()
          if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
            error "Invalid ref '${ref}'. Allowed only: v* tags or release* branches."
          }
          env.IMAGE_TAG = ref.replaceAll('/', '-')
          echo "📌 Final image tag = ${env.IMAGE_TAG}"
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

    stage('Docker Build Images') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")
          def targets = [
            "web":          "docker/app.Dockerfile",
            "worker-app":   "docker/app.Dockerfile",
            "worker-mail":  "docker/mail.Dockerfile",
            "nginx":        "docker/nginx.Dockerfile"
          ]
          targets.each { name, dockerfile ->
            sh """
              docker build \
                --no-cache \
                --build-arg GIT_REF=${params.GIT_REF} \
                --build-arg APP_VERSION=${env.IMAGE_TAG} \
                -f ${dockerfile} \
                -t ${DOCKER_REPO_PREFIX}-${name}:${env.IMAGE_TAG} .
            """
          }
        }
      }
    }

    stage('Trivy Security Scan for All Images') {
      steps {
        script {
          def imageList = [
            "${DOCKER_REPO_PREFIX}-web:${env.IMAGE_TAG}",
            "${DOCKER_REPO_PREFIX}-worker-app:${env.IMAGE_TAG}",
            "${DOCKER_REPO_PREFIX}-worker-mail:${env.IMAGE_TAG}",
            "${DOCKER_REPO_PREFIX}-nginx:${env.IMAGE_TAG}",
          ]

          imageList.each { img ->
            echo "🔍 Trivy scanning ${img} ..."
            sh """trivy image --format json --exit-code 1 --severity HIGH,CRITICAL ${img} -o trivy-${img.tokenize('/').last()}.json || true"""
          }

          archiveArtifacts artifacts: 'trivy-*.json', allowEmptyArchive: true

          // Parse all JSONs
          def totalCritical = 0
          imageList.each { img ->
            def file = "trivy-${img.tokenize('/').last()}.json"
            if (fileExists(file)) {
              def parsed = new JsonSlurper().parseText(readFile(file))
              parsed.Results.each { result ->
                if (result.Vulnerabilities) {
                  totalCritical += result.Vulnerabilities.size()
                }
              }
            }
          }

          echo "⚠ Total HIGH/CRITICAL vulnerabilities found: ${totalCritical}"

          if (totalCritical > 0 && params.TRIVY_FAIL_ACTION == 'fail-build') {
            error "❌ Trivy check failed due to HIGH/CRITICAL vulnerabilities."
          } else if (totalCritical > 0) {
            currentBuild.result = 'UNSTABLE'
            echo "⚠ Vulnerabilities found — build marked UNSTABLE."
          } else {
            echo "✅ All images passed Trivy security check."
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

            def targets = ["web","worker-app","worker-mail","nginx"]
            targets.each { name ->
              def img = "${DOCKER_REPO_PREFIX}-${name}:${env.IMAGE_TAG}"
              echo "⬆️ Pushing ${img}..."
              sh "docker push ${img}"
            }

            sh "docker logout"
          }
        }
      }
    }
  }

  post {
    always {
      echo "🔁 Pipeline completed — status: ${currentBuild.result ?: 'SUCCESS'}"
    }
    success {
      echo "🎉 SUCCESS — All images pushed with tag ${env.IMAGE_TAG}"
    }
    unstable {
      echo "⚠ UNSTABLE — Vulnerabilities found, but images pushed"
    }
    failure {
      echo "❌ FAILED — Fix errors and rerun the job"
    }
  }
}
