pipeline {
    agent any
    
    environment {
        // Configuration de base
        DOCKER_IMAGE = "demo-app"
        DOCKER_TAG = "${BUILD_NUMBER}"
        // Pour la connexion à Docker Hub si nécessaire
        // DOCKER_HUB_CREDS = credentials('docker-hub-credentials')
    }
    
    stages {
        stage('Checkout SCM') {
            steps {
                checkout scm
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh '''
                    sonar-scanner \
                      -Dsonar.projectKey=demo-app \
                      -Dsonar.projectName='Demo App' \
                      -Dsonar.sources=. \
                      -Dsonar.host.url=http://localhost:9000
                    '''
                }
                
                // Attente du Quality Gate
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    // Construction de l'image Docker
                    sh "docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} ."
                    sh "docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest"
                }
            }
        }
        
        stage('Trivy Scan') {
            steps {
                script {
                    // Utilisation de Trivy pour scanner l'image Docker à la recherche de vulnérabilités
                    sh "trivy image --severity HIGH,CRITICAL --no-progress ${DOCKER_IMAGE}:${DOCKER_TAG} > trivy-report.txt || true"
                    
                    // Publication du rapport Trivy comme artefact
                    archiveArtifacts artifacts: 'trivy-report.txt', fingerprint: true
                    
                    // Vérification des vulnérabilités critiques et échec du build si nécessaire
                    def trivyStatus = sh(script: "grep 'CRITICAL: [1-9]' trivy-report.txt || true", returnStatus: true)
                    if (trivyStatus == 0) {
                        echo "Vulnérabilités critiques détectées dans l'image Docker!"
                        // Décommentez la ligne suivante pour que le pipeline échoue en cas de vulnérabilités critiques
                        // error "Échec du build en raison de vulnérabilités critiques dans l'image Docker"
                    }
                }
            }
        }
        
        stage('Deploy') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                script {
                    echo "Déploiement de l'application..."
                    // Commandes de déploiement (exemple)
                    // sh "docker stop demo-app-container || true"
                    // sh "docker rm demo-app-container || true"
                    // sh "docker run -d --name demo-app-container -p 8080:8080 ${DOCKER_IMAGE}:${DOCKER_TAG}"
                }
            }
        }
    }
    
    post {
        always {
            // Nettoyage des ressources
            sh "docker image prune -f"
        }
        success {
            echo "Pipeline exécuté avec succès!"
        }
        failure {
            echo "Le pipeline a échoué."
        }
    }
}
