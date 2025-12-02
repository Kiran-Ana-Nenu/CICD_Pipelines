import groovy.json.JsonSlurper
import groovy.json.JsonOutput

pipeline {
  agent any

  options {
    // timestamp logs for auditing
    timestamps()
    // keep only last 10 builds' logs/artifacts if desired (optional)
    // buildDiscarder(logRotator(numToKeepStr: '10'))
  }

  parameters {
    string(name: 'GIT_REF', defaultValue: 'release/1.8', description: 'Branch (release/*) or tag (v*)')
    booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
    choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build', 'warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
    booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable debug logs (set -x, print env, system info)')
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
    GIT_URL = "xxxxxxxxx"
    DOCKER_HUB_URL = "https://index.docker.io/v1/"
    DOCKER_REPO_PREFIX = "xxxxxx"
    DOCKER_CREDENTIALS_ID = "dockerhub-creds"
    APPROVERS = "admin,adminuser"
    // ensure a default IMAGES set
    IMAGES = '[]'
  }

  stages {
    stage('Clean Workspace (Pre-build)') {
      when { expression { params.CLEAN_BEFORE } }
      steps {
        echo "🧹 Cleaning workspace..."
        cleanWs()
      }
    }

    stage('Admin Approval') {
      steps {
        script {
          // build param text
          def paramText = params.collect { k, v -> "${k} = ${v}" }.join("\n")

          // build preview tags for selected images (safe trimming & fallback)
          def ref = params.GIT_REF?.trim() ?: ''
          if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
            // Do not fail here so approver can see invalid ref? We'll error to avoid unwanted runs.
            error "❌ Invalid ref '${ref}'. Allowed only: v* tags or release* branches."
          }
          def previewTag = ref.replaceAll("/", "-")

          def selectedList = []
          if (params.BUILD_IMAGES?.trim()) {
            selectedList = params.BUILD_IMAGES.split(',')*.trim()
          }

          def imagesPreview = selectedList.collect { img ->
            "${env.DOCKER_REPO_PREFIX}-${img}:${previewTag}"
          }.join("\n")

          def msg = """Admin approval required to continue workspace cleanup.

📌 Job Parameters:
${paramText}

📦 Docker images to be built (preview):
${imagesPreview}

Proceed with build?
"""

          // show popup with parameters + preview
          def user = input(
            message: msg,
            ok: 'Approve',
            submitter: env.APPROVERS
          )
          echo "✅ Approved by: ${user}"
        }
      }
    }

    stage('Build Summary Dashboard') {
      steps {
        script {
          // ANSI color codes (works if ansi-color plugin enabled; otherwise shows raw codes)
          def BOLD = "\u001B[1m"
          def RESET = "\u001B[0m"
          def GREEN = "\u001B[32m"
          def YELLOW = "\u001B[33m"
          def BLUE = "\u001B[34m"
          def MAGENTA = "\u001B[35m"
          def CYAN = "\u001B[36m"

          def buildImagesDisplay = params.BUILD_IMAGES?.replaceAll("\\s*,\\s*", ", ") ?: ''

          def summaryRows = [
            ["🔀 Git Ref", params.GIT_REF],
            ["🧹 Clean Before Build", params.CLEAN_BEFORE ? "${GREEN}YES${RESET}" : "${YELLOW}NO${RESET}"],
            ["🔍 Trivy Fail Action", params.TRIVY_FAIL_ACTION],
            ["🩺 Debug Mode", params.DEBUG_MODE ? "${CYAN}ENABLED${RESET}" : "DISABLED"],
            ["🐳 Use Cache", params.USE_CACHE ? "YES" : "NO"],
            ["📤 Push After Build", params.PUSH_IMAGES ? "YES" : "NO"],
            ["📦 Build Images", buildImagesDisplay]
          ]

          println ""
          println "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
          println "${BOLD} 💎 BUILD CONFIGURATION DASHBOARD${RESET}"
          println "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

          summaryRows.each { row ->
            printf("%-28s : %s\n", row[0], row[1])
          }

          println "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"

          def previewTag = params.GIT_REF.trim().replaceAll("/", "-")
          def repo = env.DOCKER_REPO_PREFIX
          def previewImages = []
          if (params.BUILD_IMAGES?.trim()) {
            previewImages = params.BUILD_IMAGES.split(',')*.trim().collect { img ->
              "${repo}-${img}:${previewTag}"
            }
          }

          if (previewImages) {
            println "${BOLD}${BLUE}📦 Docker images to be built:${RESET}"
            previewImages.each { println "   ➤ ${GREEN}${it}${RESET}" }
            println ""
          } else {
            println "${YELLOW}⚠ No images selected to build${RESET}\n"
          }
        }
      }
    }

    stage('Validate Git Ref + Generate Image Tags') {
      steps {
        script {
          // normalize tag
          def ref = params.GIT_REF.trim()
          env.IMAGE_TAG = ref.replaceAll("/", "-")

          // Define all images (keys match extendedChoice values)
          def allImages = [
            "web"         : "${env.DOCKER_REPO_PREFIX}-web:${env.IMAGE_TAG}",
            "worker-app"  : "${env.DOCKER_REPO_PREFIX}-worker-app:${env.IMAGE_TAG}",
            "worker-mail" : "${env.DOCKER_REPO_PREFIX}-worker-mail:${env.IMAGE_TAG}",
            "nginx"       : "${env.DOCKER_REPO_PREFIX}-nginx:${env.IMAGE_TAG}"
          ]

          // Build selected list safely
          def selected = []
          if (params.BUILD_IMAGES?.trim()) {
            selected = params.BUILD_IMAGES.split(",")*.trim()
          }

          def selectedImages = [:]
          selected.each { img ->
            if (allImages.containsKey(img)) {
              selectedImages[img] = allImages[img]
            } else {
              echo "⚠ Ignoring unknown image selection: ${img}"
            }
          }

          if (!selectedImages) {
            echo "⚠ No valid images selected — nothing to build"
          }

          env.IMAGES = JsonOutput.toJson(selectedImages)
          echo "IMAGE_TAG = ${env.IMAGE_TAG}"
          echo "📦 Selected Docker images to build: "
          def parsed = new JsonSlurper().parseText(env.IMAGES ?: '[]')
          parsed.each { k, v -> echo " - ${k}: ${v}" }
        }
      }
    }

    stage('Checkout Code') {
      steps {
        script {
          if (params.DEBUG_MODE) {
            echo "🔧 Debug mode enabled: printing environment (partial)"
            sh "env | sort | sed -n '1,200p' || true"
          }

          // safe checkout
          checkout([$class: 'GitSCM',
                    branches: [[name: params.GIT_REF]],
                    userRemoteConfigs: [[url: env.GIT_URL]]
          ])
        }
      }
    }

    stage('Docker Build (Parallel)') {
      steps {
        script {
          def images = new JsonSlurper().parseText(env.IMAGES ?: '{}')
          if (!images) {
            echo "⚠ No images to build. Skipping Docker Build stage."
            return
          }

          def buildTasks = [:]
          def dockerPath = "docker"

          images.each { name, image ->
            buildTasks["Build ${name}"] = {
              // use dedicated workspace subdir to avoid parallel conflicts
              dir("build-${name.replaceAll('[^A-Za-z0-9_-]', '_')}") {
                script {
                  def dockerFile = ""
                  switch (name) {
                    case "web":
                    case "worker-app":
                      dockerFile = "app.Dockerfile"
                      break
                    case "worker-mail":
                      dockerFile = "mail.Dockerfile"
                      break
                    case "nginx":
                      dockerFile = "nginx.Dockerfile"
                      break
                    default:
                      error("❌ Unknown image: ${name}")
                  }

                  echo "🔨 Building ${name} -> ${image} using ${dockerFile}"
                  def noCache = params.USE_CACHE ? "" : "--no-cache"

                  // timeout to avoid stuck builds
                  timeout(time: 30, unit: 'MINUTES') {
                    sh """
                      docker build ${noCache} -f ${dockerPath}/${dockerFile} \
                        --build-arg APP_ROLE=${name} \
                        --build-arg APP_VERSION=${env.IMAGE_TAG} \
                        -t ${image} .
                    """
                  }
                }
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
          def images = new JsonSlurper().parseText(env.IMAGES ?: '{}')
          if (!images) {
            echo "⚠ No images to scan. Skipping Trivy."
            return
          }
          images.each { name, image ->
            echo "🔍 Trivy scanning ${image}"
            def outputFile = "trivy-${name}.json"
            sh "trivy image --format json --severity HIGH,CRITICAL ${image} -o ${outputFile} || true"
            archiveArtifacts artifacts: outputFile, allowEmptyArchive: true

            def jsonText = ''
            try {
              jsonText = readFile(outputFile)
            } catch (err) {
              echo "⚠ Trivy output for ${name} not found: ${err}"
              jsonText = ''
            }

            if (!jsonText?.trim()) {
              echo "⚠ No trivy JSON content for ${name}. Treating as 0 HIGH/CRITICAL."
              continue
            }

            def json = new JsonSlurper().parseText(jsonText)
            def total = 0
            json.Results?.each { r -> total += (r?.Vulnerabilities?.size() ?: 0) }

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
          def images = new JsonSlurper().parseText(env.IMAGES ?: '{}')
          if (!images) {
            echo "⚠ No images to push. Skipping Push stage."
            return
          }

          withCredentials([usernamePassword(credentialsId: env.DOCKER_CREDENTIALS_ID, usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            sh "echo ${PASS} | docker login ${DOCKER_HUB_URL} -u ${USER} --password-stdin"

            images.each { name, image ->
              retry(2) {
                echo "📤 Pushing ${image}"
                sh "docker push ${image}"
              }
            }

            sh "docker logout || true"
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
      echo "🎉 SUCCESS — Selected Docker images processed"
    }
    unstable {
      echo "⚠ UNSTABLE — Issues found (e.g., Trivy)."
    }
    failure {
      echo "❌ FAILED — see logs"
    }
  }
}
