pipeline {
  agent none

  parameters {
    // choice(name: 'BUILD_SLAVE', choices: ['Build-T','Build-M','Build-R'], description: 'Select dynamic slave label')
    string(name: 'GIT_REF', defaultValue: 'release/1.0', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'SKIP_TESTS', defaultValue: false, description: 'Skip Maven tests?')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build','warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
  }

  environment {
    // 🔥 You provide these in Jenkins > Manage > System > Global properties OR in the Pipeline job
    GIT_URL        = "https://github.com/Kiran-Ana-Nenu/Springboot_App.git"         // <── injected as environment variable
    DOCKER_HUB_URL = "https://index.docker.io/v1/"               // <── used for login
    DOCKER_REPO    = "kiranpayyavuala/sslexpire_application"                // <── org/repo (image name)
    
    DOCKER_CREDENTIALS_ID = "dockerhub-creds"
    MAVEN_OPTS = "-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn"
  }

  stages {

    // stage('Allocate Agent') {
    //   agent { label "${params.BUILD_SLAVE}" }
    // }

    stage('Validate Git Ref') {
      steps {
        script {
          def ref = params.GIT_REF.trim()
          if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
            error "Invalid ref: ${ref}. Only v* tags or release* branches allowed."
          }
          env.REF_SANITIZED = ref.replaceAll('/', '-')
          env.IMAGE_TAG = env.REF_SANITIZED
          env.FULL_IMAGE = "${env.DOCKER_REPO}:${env.IMAGE_TAG}"
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
          def skipFlag = params.SKIP_TESTS ? "-DskipTests=true" : ""
          sh "mvn -B clean install ${skipFlag}"
        }
      }
      post {
        always {
          junit allowEmptyResults: true, testResults: '**/target/surefire-reports/*.xml'
        }
      }
    }

    stage('Docker Build (Optimized)') {
      steps {
        script {
          // 🔥 --no-cache + BuildArgs for multistage Dockerfile optimizations
          sh """
            echo "Building Docker image WITHOUT cache: ${FULL_IMAGE}"
            docker build \\
              --no-cache \\
              --build-arg GIT_REF=${params.GIT_REF} \\
              --build-arg APP_VERSION=${env.IMAGE_TAG} \\
              -t ${FULL_IMAGE} .
          """
        }
      }
    }

    stage('Trivy Scan') {
      steps {
        script {
          sh "trivy image --format table --exit-code 1 --severity HIGH,CRITICAL ${FULL_IMAGE} || true | tee trivy.txt"
          def hasCritical = sh(script: "grep -E 'HIGH|CRITICAL' trivy.txt || true", returnStdout: true).trim()
          if (hasCritical && params.TRIVY_FAIL_ACTION == 'fail-build') {
            error "Trivy found HIGH/CRITICAL vulnerabilities."
          }
          if (hasCritical) {
            currentBuild.result = 'UNSTABLE'
          }
        }
      }
    }

    stage('Push to Docker Hub') {
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
      echo "🎉 Build Successful. Docker pushed: ${env.FULL_IMAGE}"
    }
    unstable {
      echo "⚠ Build unstable (Trivy warnings). Image pushed: ${env.FULL_IMAGE}"
    }
    failure {
      echo "❌ Build failed."
    }
  }
}
