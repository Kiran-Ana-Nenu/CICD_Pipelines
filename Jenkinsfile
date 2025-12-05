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
    options { timestamps() }

    parameters {
        string(name: 'GIT_REF', defaultValue: 'release/1.8', description: 'Branch (release/*) or tag (v*)')
        booleanParam(name: 'CLEAN_BEFORE', defaultValue: false, description: 'Clean workspace before build')
        choice(name: 'TRIVY_FAIL_ACTION', choices: ['fail-build', 'warn-only'], description: 'Action on HIGH/CRITICAL vulnerabilities')
        booleanParam(name: 'DEBUG_MODE', defaultValue: false, description: 'Enable debug logs')
        extendedChoice(
            name: 'BUILD_IMAGES',
            type: 'PT_CHECKBOX',
            value: 'all,web,worker-app,worker-mail,nginx',
            description: 'Select which images to build. Choose "all" to build all images.',
            defaultValue: 'all'
        )
        booleanParam(name: 'DOCKER_PRUNE', defaultValue: true, description: 'Enable Docker prune before build')
        booleanParam(name: 'USE_CACHE', defaultValue: true, description: 'Enable Docker build cache')
        booleanParam(name: 'PUSH_IMAGES', defaultValue: true, description: 'Push built images to Docker Hub')
        booleanParam(name: 'Parallelbuild', defaultValue: true, description: 'Build Docker images in parallel')
    }

    environment {
        GIT_URL = "https://github.com/Kiran-Ana-Nenu/ssl_monitoring.git"
        DOCKER_HUB_URL = "https://index.docker.io/v1/"
        DOCKER_REPO_PREFIX = "kiranpayyavuala/sslexpire_application"
        DOCKER_CREDENTIALS_ID = "dockerhub-creds"
        APPROVERS = "admin,adminuser"
        // Ensure TRIVY template filename here matches the file in your repo
        TRIVY_TEMPLATE = "trivy-report-premium.tpl"
    }

    stages {

        stage('Clean Workspace (Pre-build)') {
            when { expression { params.CLEAN_BEFORE } }
            steps { cleanWs() }
        }

        stage('Admin Approval') {
            steps {
                script {
                    def paramText = params.collect { k,v -> "${k} = ${v}" }.join("\n")
                    input message: """Admin approval required.

📌 Job Parameters:
${paramText}""", ok: 'Approve', submitter: env.APPROVERS
                }
            }
        }

        stage('Validate Git Ref + Generate Image Tags') {
            steps {
                script {
                    def ref = params.GIT_REF.trim()
                    if (!(ref ==~ /^v.*/ || ref ==~ /^release.*/ || ref ==~ /^release\/.*/)) {
                        error "❌ Invalid ref '${ref}'"
                    }
                    env.IMAGE_TAG = ref.replaceAll("/", "-")

                    def allImages = [
                        "web"        : "${env.DOCKER_REPO_PREFIX}-web:${env.IMAGE_TAG}",
                        "worker-app" : "${env.DOCKER_REPO_PREFIX}-worker-app:${env.IMAGE_TAG}",
                        "worker-mail": "${env.DOCKER_REPO_PREFIX}-worker-mail:${env.IMAGE_TAG}",
                        "nginx"      : "${env.DOCKER_REPO_PREFIX}-nginx:${env.IMAGE_TAG}"
                    ]

                    // CPS-safe parsing of BUILD_IMAGES param
                    def selected = params.BUILD_IMAGES?.split(",")?.collect { it.trim() }
                    def selectedImages = [:]

                    if (!selected || selected.contains("all")) {
                        echo "📦 Building ALL images"
                        selectedImages = allImages
                    } else {
                        selected.each { img ->
                            if (allImages.containsKey(img)) selectedImages[img] = allImages[img]
                        }
                    }

                    if (selectedImages.isEmpty()) {
                        error "❌ No valid images selected to build"
                    }

                    env.IMAGES = JsonOutput.toJson(selectedImages)
                    echo "📦 Docker images to build:"
                    readJSON(text: env.IMAGES).each { k,v -> echo " - ${k}: ${v}" }
                }
            }
        }

        stage('Checkout Code') {
            steps {
                script {
                    sh(params.DEBUG_MODE ? "set -x ; true" : "true")
                    checkout([$class: 'GitSCM',
                        branches: [[name: params.GIT_REF]],
                        userRemoteConfigs: [[url: env.GIT_URL]],
                        extensions: [[$class: 'CleanBeforeCheckout']]
                    ])
                }
            }
        }

        stage('Docker Cleanup') {
            when { expression { params.DOCKER_PRUNE } }
            steps {
                script {
                    echo "🧹 Cleaning Docker cache..."
                    sh 'docker system prune --all --force --volumes || true'
                }
            }
        }

        stage('Docker Build (Parallel/Serial)') {
            steps {
                script {
                    echo "⏳ Initializing Buildx..."
                    sh '''
                        docker buildx rm jenkins-builder || true
                        docker buildx create --name jenkins-builder --use
                        docker buildx inspect --bootstrap
                    '''

                    def images = readJSON(text: env.IMAGES)
                    def dockerPath = "docker"

                    if (params.Parallelbuild) {
                        echo "🔥 Parallel build enabled"
                        def buildTasks = [:]
                        images.each { name, image ->
                            buildTasks["Build ${name}"] = {
                                script {
                                    def dockerFile = ""
                                    switch(name) {
                                        case "web":
                                        case "worker-app": dockerFile = "app.Dockerfile"; break
                                        case "worker-mail": dockerFile = "mail.Dockerfile"; break
                                        case "nginx": dockerFile = "nginx.Dockerfile"; break
                                    }
                                    echo "\n==================== BUILDING ${name} ====================\n"
                                    sh """
                                        docker buildx build --load ${params.USE_CACHE ? "" : "--no-cache"} \
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
                        echo "🐢 Serial build mode"
                        images.each { name, image ->
                            def dockerFile = ""
                            switch(name) {
                                case "web":
                                case "worker-app": dockerFile = "app.Dockerfile"; break
                                case "worker-mail": dockerFile = "mail.Dockerfile"; break
                                case "nginx": dockerFile = "nginx.Dockerfile"; break
                            }
                            echo "\n==================== BUILDING ${name} ====================\n"
                            sh """
                                docker buildx build --load ${params.USE_CACHE ? "" : "--no-cache"} \
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

        // ===== TRIVY SCAN (always produce full HTML, then separately check HIGH/CRITICAL) =====
        stage('Trivy Scan') {
            steps {
                script {
                    def images = readJSON(text: env.IMAGES)
                    def unstableImages = []

                    // Template path in workspace (must be present in repo)
                    def templatePath = "${env.WORKSPACE}/${env.TRIVY_TEMPLATE}"
                    if (!fileExists(templatePath)) {
                        error "❌ Trivy template not found at ${templatePath}. Add ${env.TRIVY_TEMPLATE} to repo root."
                    }

                    images.each { name, image ->
                        echo "🔍 Trivy scanning ${image} (full report + HC check)"

                        // 1) Produce full HTML with all severities (so template always has data)
                        sh """
                            trivy image \
                                --scanners vuln \
                                --format template \
                                --template "@${templatePath}" \
                                --exit-code 0 \
                                --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
                                ${image} > trivy-${name}.html || true
                        """

                        // 2) Guarantee non-empty HTML (fallback)
                        def reportFile = "trivy-${name}.html"
                        if (!fileExists(reportFile) || readFile(reportFile).trim().length() == 0) {
                            echo "⚠ Trivy produced empty HTML for ${name} — writing fallback placeholder"
                            writeFile file: reportFile, text: """
                                <html><body><h3>⚠ Trivy report unavailable for ${name}</h3></body></html>
                            """
                        }

                        // Archive for download
                        archiveArtifacts artifacts: reportFile, allowEmptyArchive: false

                        // 3) Run a quick Trivy check that exits 1 if HIGH/CRITICAL present (no output)
                        def hcStatus = sh(
                            returnStatus: true,
                            script: "trivy image --severity HIGH,CRITICAL --exit-code 1 ${image} >/dev/null 2>&1"
                        )

                        if (hcStatus == 1) {
                            // HIGH/CRITICAL found
                            unstableImages << name
                            if (params.TRIVY_FAIL_ACTION == 'fail-build') {
                                error "❌ HIGH/CRITICAL vulnerabilities detected in ${name}"
                            } else {
                                currentBuild.result = 'UNSTABLE'
                                echo "⚠ Marking build UNSTABLE due to HIGH/CRITICAL vulnerabilities in ${name}"
                            }
                        } else {
                            echo "🟢 No HIGH/CRITICAL vulnerabilities found in ${name}"
                        }
                    }

                    env.UNSTABLE_IMGS = unstableImages.join(",")
                    if (unstableImages) {
                        echo "\n🚨 UNSTABLE IMAGES DETECTED:\n${unstableImages.join('\n')}"
                    } else {
                        echo "\n🟢 All images passed Trivy check (no HIGH/CRITICAL)"
                    }
                }
            }
        }

        stage('Publish Security Reports') {
            steps {
                script {
                    def images = readJSON(text: env.IMAGES)
                    images.each { name, image ->
                        // publishHTML requires the HTML Publisher plugin
                        publishHTML(target: [
                            reportName: "🔐 Trivy Report — ${name}",
                            reportDir: ".",
                            reportFiles: "trivy-${name}.html",
                            keepAll: true,
                            allowMissing: true,
                            alwaysLinkToLastBuild: true
                        ])
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
            script {
                if (env.UNSTABLE_IMGS?.trim()) {
                    echo "\n================= FINAL STATUS — UNSTABLE IMAGES ================="
                    env.UNSTABLE_IMGS.split(",").each { echo " - ${it}" }
                    echo "==================================================================\n"
                }
            }
        }
        success { echo "🎉 SUCCESS — Selected Docker images pushed successfully" }
        unstable { echo "⚠ UNSTABLE — Images built but Trivy found vulnerabilities" }
        failure { echo "❌ FAILED — see logs" }
    }
}
