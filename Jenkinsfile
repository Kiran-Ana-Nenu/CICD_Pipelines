pipeline {

  // 👇 This is the only agent definition — Jenkins will pick the default executor automatically
  agent any

  parameters {
    string(name: 'GIT_REF', defaultValue: 'release/1.0', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'SKIP_TESTS', defaultValue: false, description: 'Skip Maven tests?')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build','warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
  }

  environment {
    // 👇 Provided from Jenkins global env or job env
    GIT_URL        = "https://github.com/Kiran-Ana-Nenu/Springboot_App.git"
    DOCKER_HUB_URL = "https://index.docker.io/v1/"
    DOCKER_REPO    = "kiranpayyavuala/sslexpire_application"

    DOCKER_CREDENTIALS_ID = "dockerhub-creds"
  }

  stages {

    stage('Validate Git Ref') {
      steps {
        script {
          def ref = params.GIT_REF.trim()
          if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
            error "❌ Invalid ref: '${ref}'. Allowed: tag v* or branch release*."
          }
          env.IMAGE_TAG = ref.replaceAll('/', '-')
          env.FULL_IMAGE = "${env.DOCKER_REPO}:${env.IMAGE_TAG}"
          echo "IMAGE_TAG = ${env.IMAGE_TAG}"
          echo "FULL_IMAGE = ${env.FULL_IMAGE}"
        }
      }
    }

    stage('Checkout Code') {
      steps {
        checkout([$class: 'GitSCM',
          branches: [[name: params.GIT_REF]],
          userRemoteConfigs: [[url: env.GIT_URL]]
        ])
      }
    }

    stage('Maven Build') {
      steps {
        script {
          def skip = params.SKIP_TESTS ? "-DskipTests=true" : ""
          sh "mvn -B clean install ${skip}"
        }
      }
    }

    stage('Docker Build (no cache + optimized)') {
      steps {
        sh """
          echo "Building Docker image: ${FULL_IMAGE}"
          docker build \\
            --no-cache \\
            --build-arg GIT_REF=${params.GIT_REF} \\
            --build-arg APP_VERSION=${env.IMAGE_TAG} \\
            -t ${FULL_IMAGE} .
        """
      }
    }

    stage('Trivy Scan') {
      steps {
        script {
          sh "trivy image --format table --exit-code 1 --severity HIGH,CRITICAL ${FULL_IMAGE} || true | tee trivy.txt"

          def critical = sh(script: "grep -E 'HIGH|CRITICAL' trivy.txt || true", returnStdout: true).trim()
          if (critical && params.TRIVY_FAIL_ACTION == 'fail-build') {
            error "❌ Trivy found HIGH/CRITICAL vulnerabilities."
          }
          if (critical) {
            currentBuild.result = 'UNSTABLE'
            echo "⚠ Trivy found HIGH/CRITICAL issues — build marked UNSTABLE."
          } else {
            echo "✔ No HIGH/CRITICAL vulnerabilities."
          }
        }
      }
    }

    stage('Push Image to Docker Hub') {
      steps {
        script {
          withCredentials([usernamePassword(credentialsId: env.DOCKER_CREDENTIALS_ID, usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            sh """
              echo "${PASS}" | docker login ${DOCKER_HUB_URL} -u "${USER}" --password-stdin
              docker push ${FULL_IMAGE}
              docker logout
            """
          }
        }
      }
    }
  }

  post {
    success {
      echo "🎉 SUCCESS — Docker pushed: ${env.FULL_IMAGE}"
    }
    unstable {
      echo "⚠ UNSTABLE — Docker pushed (Trivy warnings): ${env.FULL_IMAGE}"
    }
    failure {
      echo "❌ FAILED — Check Jenkins logs"
    }
  }
}
