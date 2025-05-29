pipeline {
    agent any

    environment {
        SONARQUBE_INSTALLATION = 'sonarQube'

        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        TARGET_URL = 'http://demo.testfire.net'
        MISTRAL_API_KEY = credentials('taha-jenkins')
        MISTRAL_API_URL = 'https://api.mistral.ai/v1/chat/completions'

        APP_NAME = "${env.JOB_NAME}-${env.BUILD_NUMBER}".toLowerCase().replaceAll(/[^a-z0-9-]/, '-')
        IMAGE_NAME = "demo-app"
        K8S_NAMESPACE = "secure-namespace"
        DOCKER_REGISTRY = "localhost:5000"
        KUBECONFIG = credentials('kubeconfig')
    }

    stages {
        stage('Checkout') {
            steps {
                echo "🔄 Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app'

                sh '''
                    mkdir -p k8s-templates
                    mkdir -p k8s-deploy
                    mkdir -p security-reports
                    mkdir -p scripts
                '''
            }
        }

        stage('Analyse SonarQube') {
            steps {
                script {
                    try {
                        echo "🚀 Début de l'analyse SonarQube..."

                        writeFile file: 'sonar-project.properties', text: '''# Configuration SonarQube
sonar.projectKey=demo-app
sonar.projectName=Demo App Security Pipeline
sonar.sources=.
sonar.exclusions=**/node_modules/**,**/target/**,**/*.log,**/k8s-templates/**,**/k8s-deploy/**,**/security-reports/**,**/scripts/**
sonar.sourceEncoding=UTF-8
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.java.source=11
sonar.python.coverage.reportPaths=coverage.xml
sonar.qualitygate.wait=false
'''

                        withSonarQubeEnv('sonarQube') {
                            sh '''
                                if ! command -v sonar-scanner >/dev/null 2>&1; then
                                    wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-linux.zip
                                    unzip -q sonar-scanner-cli-4.8.0.2856-linux.zip
                                    SCANNER_CMD="./sonar-scanner-4.8.0.2856-linux/bin/sonar-scanner"
                                else
                                    SCANNER_CMD="sonar-scanner"
                                fi

                                ${SCANNER_CMD} \\
                                    -Dsonar.projectKey=demo-app \\
                                    -Dsonar.projectName="Demo App Security Pipeline" \\
                                    -Dsonar.sources=. \\
                                    -Dsonar.exclusions="**/node_modules/**,**/target/**,**/*.log,**/k8s-templates/**,**/security-reports/**" \\
                                    -Dsonar.host.url="${SONAR_HOST_URL}" \\
                                    -Dsonar.login="${SONAR_AUTH_TOKEN}"
                            '''
                        }
                        echo "✅ Analyse SonarQube terminée !"
                    } catch (Exception e) {
                        echo "❌ Erreur SonarQube: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Quality Gate SonarQube') {
            steps {
                script {
                    try {
                        timeout(time: 3, unit: 'MINUTES') {
                            def qg = waitForQualityGate()
                            if (qg.status != 'OK') {
                                echo "⚠️ Quality Gate: ${qg.status}"
                                currentBuild.result = 'UNSTABLE'
                            } else {
                                echo "✅ Quality Gate réussi"
                            }
                        }
                    } catch (e) {
                        echo "⏱️ Timeout Quality Gate: ${e.message}"
                    }
                }
            }
        }

        stage('Analyse SCA avec Trivy') {
            steps {
                script {
                    try {
                        echo '🔍 Analyse des dépendances avec Trivy (SCA)...'
                        sh '''
                            trivy fs --scanners vuln,license . > security-reports/trivy-sca-report.txt || echo "⚠️ Trivy SCA échoué"
                        '''
                    } catch (e) {
                        echo "❌ SCA erreur: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Build de l’image Docker') {
            steps {
                script {
                    echo '🏗️ Construction de l’image Docker...'
                    sh '''
                        docker build -t ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} .
                        docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                    '''
                }
            }
        }

        stage('Scan de l’image avec Trivy') {
            steps {
                script {
                    echo '🔎 Scan de l’image avec Trivy...'
                    sh '''
                        trivy image ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} --format table --output security-reports/image-scan-report.txt
                    '''
                }
            }
        }

        stage('Signature de l’image avec Cosign') {
            steps {
                script {
                    echo '✍️ Signature avec Cosign...'
                    withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PASSWORD')]) {
                        sh '''
                            cosign sign --key env://COSIGN_PASSWORD ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                        '''
                    }
                }
            }
        }

        stage('Analyse DAST avec ZAP') {
            steps {
                script {
                    echo "🧪 Analyse dynamique avec ZAP..."
                    sh '''
                        docker run -t ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -r zap-report.html || true
                        mv zap-report.html security-reports/
                    '''
                }
            }
        }

        stage('Déploiement sur Kubernetes') {
            steps {
                script {
                    echo "🚀 Déploiement sur Kubernetes..."

                    writeFile file: 'k8s-deploy/deployment.yaml', text: """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${APP_NAME}
  namespace: ${K8S_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${APP_NAME}
  template:
    metadata:
      labels:
        app: ${APP_NAME}
    spec:
      containers:
      - name: ${APP_NAME}
        image: ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
        securityContext:
          runAsUser: 1000
          runAsNonRoot: true
          readOnlyRootFilesystem: true
"""

                    sh '''
                        echo "${KUBECONFIG}" > kubeconfig.yaml
                        export KUBECONFIG=$(pwd)/kubeconfig.yaml
                        kubectl apply -f k8s-deploy/deployment.yaml
                    '''
                }
            }
        }
    }

    post {
        always {
            echo '🧹 Nettoyage et archivage...'
            archiveArtifacts artifacts: '**/security-reports/*.txt, **/security-reports/*.html', allowEmptyArchive: true
            sh '''
                rm -rf sonar-scanner-*
                rm -f *.zip
                rm -f kubeconfig.yaml
            '''
        }

        success {
            echo '✅ Pipeline terminé avec succès!'
        }

        unstable {
            echo '⚠️ Pipeline terminé avec des avertissements!'
        }

        failure {
            echo '❌ Pipeline échoué!'
        }
    }
}
