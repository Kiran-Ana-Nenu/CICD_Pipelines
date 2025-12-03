/*
================================================================================
📌 PIPELINE DESCRIPTION — End-to-End Docker Build & Security Scan Workflow
--------------------------------------------------------------------------------
Descreption : This Jenkins pipeline automates Docker image builds for multiple services, performs vulnerability scanning, and optionally pushes images to Docker Hub.
              The pipeline is parameter-driven and suitable for controlled production deployments.
Author    : Kiran
Version   : python image build 1.3
Date      : Dec 3rd, 2025
Ticket No : DevOps-4532
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🏗 HIGH-LEVEL FLOW
1️⃣ Receive input parameters from user (Git ref, images to build, cache option, etc.)
2️⃣ Optional workspace cleanup before build
3️⃣ Manual approval gate for authorized users before performing any build action
4️⃣ Validate the Git reference and dynamically generate Docker image tags
5️⃣ Checkout source code from Git repository
6️⃣ Build Docker images for selected services:
      • Parallel or Serial execution based on `Parallelbuild` parameter
7️⃣ Scan each image with Trivy and determine build status (FAIL / UNSTABLE / OK)
8️⃣ Optionally push built images to Docker Hub

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 KEY FEATURES
✔ Supports selective image builds (`BUILD_IMAGES` checkbox)
✔ Generates Docker tags based on Git branch / tag (e.g., `release/1.8` → `release-1.8`)
✔ Secure manual approval step (only users defined in `APPROVERS`)
✔ Parallel or serial build mode controlled by parameter `Parallelbuild`
✔ Trivy scanning with configurable behavior:
     • fail-build  → stop pipeline on HIGH/CRITICAL vulnerabilities
     • warn-only   → mark build UNSTABLE and continue
✔ Docker cache can be enabled/disabled via `USE_CACHE`
✔ Optional push to Docker Hub via `PUSH_IMAGES`

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👤 MANUAL APPROVAL GATE
Before any build/deploy action, the pipeline:
  • Displays all input parameters in a popup dialog
  • Requires approval from a submitter in `env.APPROVERS`
  • Captures and logs the approving user name

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧱 DOCKER IMAGE MATRIX
Each service corresponds to a Dockerfile:
  • web          → app.Dockerfile
  • worker-app   → app.Dockerfile
  • worker-mail  → mail.Dockerfile
  • nginx        → nginx.Dockerfile

만 The pipeline builds only the services selected in the `BUILD_IMAGES` parameter.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡 SECURITY
🔐 Credentials are stored securely in Jenkins as `dockerhub-creds`
🔒 Approval stage requires authorized usernames
🔍 Trivy scanning prevents vulnerable images from being deployed unnoticed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 RESULT OF EXECUTION
If completed successfully:
  ✔ All selected Docker images are built
  ✔ Scanned and validated for HIGH/CRITICAL vulnerabilities
  ✔ Pushed to Docker Hub (if PUSH_IMAGES = true)

If vulnerabilities exist with `warn-only`, build results IN UNSTABLE but continues.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💡 IDEAL USE CASES
🟢 Production image builds
🟢 Controlled rollouts where approvals are required
🟢 Multi-service microservice repositories
🟢 Security-first CI pipelines with scanning enforcement

================================================================================
*/

import groovy.json.JsonSlurper
import groovy.json.JsonOutput

pipeline {
    agent any
    options {
        timestamps()
    }

    parameters {
        string(name: 'GIT_REF', defaultValue: 'release/1.8', description: 'Branch (release/*) or tag (v*)')
        booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
        choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build', 'warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
        booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable debug logs')
        extendedChoice(
            name: 'BUILD_IMAGES',
            type: 'PT_CHECKBOX',
            value: 'web,worker-app,worker-mail,nginx',
            description: 'Select which images to build'
        )
        booleanParam(name: 'USE_CACHE', defaultValue: true, description: 'Enable Docker build cache')
        booleanParam(name: 'PUSH_IMAGES', defaultValue: true, description: 'Push built images to Docker Hub')

        /* NEW */
        booleanParam(name: 'Parallelbuild', defaultValue: true, description: 'Build Docker images in parallel (disable for serial build)')
    }

    environment {
        GIT_URL = "https://github.com/Kiran-Ana-Nenu/ssl_monitoring.git"
        DOCKER_HUB_URL = "https://index.docker.io/v1/"
        DOCKER_REPO_PREFIX = "kiranpayyavuala/sslexpire_application"
        DOCKER_CREDENTIALS_ID = "dockerhub-creds"
        APPROVERS = "admin,adminuser"
        // IMAGES = '[]' // default
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
                    def paramText = params.collect { k, v -> "${k} = ${v}" }.join("\n")
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

        stage('Validate Git Ref + Generate Image Tags') {
            steps {
                script {
                    def ref = params.GIT_REF.trim()
                    if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
                        error "❌ Invalid ref '${ref}'. Allowed only: v* tags or release* branches."
                    }

                    env.IMAGE_TAG = ref.replaceAll("/", "-")

                    def allImages = [
                        "web"        : "${env.DOCKER_REPO_PREFIX}-web:${env.IMAGE_TAG}",
                        "worker-app" : "${env.DOCKER_REPO_PREFIX}-worker-app:${env.IMAGE_TAG}",
                        "worker-mail": "${env.DOCKER_REPO_PREFIX}-worker-mail:${env.IMAGE_TAG}",
                        "nginx"      : "${env.DOCKER_REPO_PREFIX}-nginx:${env.IMAGE_TAG}"
                    ]

                    def selectedImages = [:]
                    params.BUILD_IMAGES.split(",").each { img ->
                        img = img.trim()
                        if (allImages.containsKey(img)) selectedImages[img] = allImages[img]
                    }

                    if (selectedImages.isEmpty()) {
                        error "❌ No images selected in BUILD_IMAGES. Build cannot continue."
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

        stage('Docker Build (Parallel/Serial)') {
            steps {
                script {
                    def images = readJSON(text: env.IMAGES)
                    def dockerPath = "docker"

                    if (params.Parallelbuild) {
                        echo "🔥 Parallel build mode enabled"
                        def buildTasks = [:]

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

                                    echo "🔨 Building ${name} → ${image} using ${dockerFile}"
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

                    } else {
                        echo "🐢 Serial mode enabled — building one image at a time"
                        images.each { name, image ->
                            def dockerFile = ""
                            switch (name) {
                                case "web":
                                case "worker-app": dockerFile = "app.Dockerfile"; break
                                case "worker-mail": dockerFile = "mail.Dockerfile"; break
                                case "nginx": dockerFile = "nginx.Dockerfile"; break
                                default: error("❌ Unknown image: ${name}")
                            }

                            echo "🔨 Building ${name} → ${image} using ${dockerFile}"
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
