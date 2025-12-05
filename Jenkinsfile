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
        APP_REPO = "${env.WORKSPACE}"                       // ssl_monitoring repo root
        DOCKER_HUB_URL = "https://index.docker.io/v1/"
        DOCKER_REPO_PREFIX = "kiranpayyavuala/sslexpire_application"
        DOCKER_CREDENTIALS_ID = "dockerhub-creds"
        APPROVERS = "admin,adminuser"
        TRIVY_TEMPLATE = "${env.WORKSPACE}/scripts/trivy-report-template.tpl"
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

                    def selected = params.BUILD_IMAGES?.split(",")?.collect { it.trim() }
                    def selectedImages = [:]
                    if (!selected || selected.contains("all")) {
                        selectedImages = allImages
                    } else {
                        selected.each { img -> if (allImages.containsKey(img)) selectedImages[img] = allImages[img] }
                    }

                    if (selectedImages.isEmpty()) { error "❌ No valid images selected" }

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
                        userRemoteConfigs: [[url: "https://github.com/Kiran-Ana-Nenu/ssl_monitoring.git"]],
                        extensions: [[$class: 'CleanBeforeCheckout']]
                    ])
                }
            }
        }

        stage('Docker Cleanup and Docker Build (Parallel/Serial)') {
            steps {
                script {
                    if (params.DOCKER_PRUNE) {
                        echo "🧹 Cleaning Docker cache..."
                        sh 'docker system prune --all --force --volumes || true'
                    }

                    echo "⏳ Initializing Buildx..."
                    sh '''
                        docker buildx rm jenkins-builder || true
                        docker buildx create --name jenkins-builder --use
                        docker buildx inspect --bootstrap
                    '''

                    def images = readJSON(text: env.IMAGES)
                    def dockerPath = "${env.APP_REPO}/docker"

                    def buildImage = { name, image ->
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
                              -t ${image} ${APP_REPO}
                        """

                        echo "🔍 Running Trivy scan for ${name}"
                        sh "bash ${APP_REPO}/scripts/trivy-report.sh ${image} ${env.IMAGE_TAG} ${APP_REPO}/trivy-reports"
                        archiveArtifacts artifacts: "trivy-reports/trivy-${name}.html", allowEmptyArchive: false
                    }

                    if (params.Parallelbuild) {
                        def buildTasks = [:]
                        images.each { name, image -> buildTasks["Build ${name}"] = { buildImage(name, image) } }
                        parallel buildTasks
                    } else {
                        images.each { name, image -> buildImage(name, image) }
                    }
                }
            }
        }

        stage('Trivy Scan Summary') {
            steps {
                sh "bash ${APP_REPO}/scripts/generate-trivy-summary.sh"
                archiveArtifacts artifacts: "trivy-reports/trivy-summary.html", allowEmptyArchive: false
            }
        }

        stage('Publish Security Reports') {
            steps {
                publishHTML(target: [
                    reportName: "🔐 Trivy Reports",
                    reportDir: "trivy-reports",
                    reportFiles: "*.html",
                    keepAll: true,
                    allowMissing: true,
                    alwaysLinkToLastBuild: true
                ])
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
        success { echo "🎉 SUCCESS — Selected Docker images pushed successfully" }
        unstable { echo "⚠ UNSTABLE — Images built but Trivy found vulnerabilities" }
        failure { echo "❌ FAILED — see logs" }
    }
}
