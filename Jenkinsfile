 pipeline {

  agent any
//   tools {
//     jdk 'jdk-21'          // ensure JDK 21 is configured in Jenkins Global Tool Config
//     maven 'maven-3.9.9'   // ensure Maven tool exists
//   }
  parameters {
    string(name: 'GIT_REF', defaultValue: 'release/1.0', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
    booleanParam(name: 'SKIP_TESTS', defaultValue: false, description: 'Skip Maven tests?')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build','warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
    booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable debug logs (set -x, print env, system info)')
  }

 environment {
    // 👇 Provided from Jenkins global env or job env
    GIT_URL        = "https://github.com/Kiran-Ana-Nenu/Springboot_App.git"
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


    // stage('Debug Info (Optional)') {
    //   when { expression { return params.DEBUG_MODE } }
    //   steps {
    //     echo "🔍 DEBUG MODE ENABLED"
    //     sh '''
    //       echo "===== SYSTEM DEBUG INFO ====="
    //       echo "Hostname: $(hostname)"
    //       echo "User: $(whoami)"
    //       echo "Workspace: $WORKSPACE"
    //       echo "===== ENVIRONMENT ====="
    //       env | sort
    //       echo "===== DOCKER VERSION ====="
    //       docker --version || true
    //       echo "===== MAVEN VERSION ====="
    //       mvn --version || true
    //     '''
    //   }
    // }

    stage('Validate Git Ref') {
      steps {
        script {
          def ref = params.GIT_REF.trim()
          if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
            error "Invalid ref '${ref}'. Allowed only: v* tags or release* branches."
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
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")
          checkout([$class: 'GitSCM',
            branches: [[name: params.GIT_REF]],
            userRemoteConfigs: [[url: env.GIT_URL]]
          ])
        }
      }
    }

    stage('Maven Build') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")
          def skip = params.SKIP_TESTS ? "-DskipTests=true" : ""
          sh "mvn -B clean install ${skip}"
        }
      }
      post {
        always {
          junit allowEmptyResults: true, testResults: '**/target/surefire-reports/*.xml'
          archiveArtifacts allowEmptyArchive: true, artifacts: '**/target/*.jar'
        }
      }
    }

    stage('Docker Build (no cache + optimized)') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")
          sh """
            docker build \\
              --no-cache \\
              --build-arg GIT_REF=${params.GIT_REF} \\
              --build-arg APP_VERSION=${env.IMAGE_TAG} \\
              -t ${FULL_IMAGE} .
          """
        }
      }
    }

import groovy.json.JsonSlurper

stage('Trivy Scan') {
  steps {
    script {
      echo "🔍 Running Trivy scan on ${FULL_IMAGE} (JSON output only)..."

      // Save JSON only
      sh "trivy image --format json --exit-code 1 --severity HIGH,CRITICAL ${FULL_IMAGE} -o trivy.json || true"

      archiveArtifacts artifacts: 'trivy.json', allowEmptyArchive: true

      // Read JSON safely
      def jsonText = readFile('trivy.json')
      def json = new JsonSlurper().parseText(jsonText)

      def criticalCount = 0
      json.Results.each { result ->
          if (result.Vulnerabilities) {
              criticalCount += result.Vulnerabilities.size()
          }
      }

      echo "⚠ Number of HIGH/CRITICAL vulnerabilities found: ${criticalCount}"

      if (criticalCount > 0 && params.TRIVY_FAIL_ACTION == 'fail-build') {
          error "❌ Trivy HIGH/CRITICAL vulnerability check failed with ${criticalCount} vulnerabilities."
      } else if (criticalCount > 0) {
          currentBuild.result = 'UNSTABLE'
          echo "⚠ Trivy found vulnerabilities — build marked UNSTABLE."
      } else {
          echo "✅ No HIGH/CRITICAL vulnerabilities found."
      }
    }
  }
}





    stage('Push Image to Docker Hub') {
      steps {
        script {
          sh(params.DEBUG_MODE ? "set -x ; true" : "true")
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
    always {
      echo "🔁 Pipeline completed — status: ${currentBuild.result ?: 'SUCCESS'}"
    }
    success {
      echo "🎉 SUCCESS — Image pushed: ${env.FULL_IMAGE}"
    }
    unstable {
      echo "⚠ UNSTABLE — Image pushed but Trivy detected vulnerabilities"
    }
    failure {
      echo "❌ FAILED — See logs"
    }
  }
}
