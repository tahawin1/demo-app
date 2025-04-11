pipeline {
    agent any

    environment {
        SONARQUBE_INSTALLATION = 'sonarQube'
        IMAGE_NAME = 'demo-app'
        TAG = 'latest'
    }

    stages {
        stage('Checkout') {
            steps {
                echo "📦 Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app'
            }
        }

        stage('Analyse SonarQube') {
            steps {
                withSonarQubeEnv("${SONARQUBE_INSTALLATION}") {
                    sh '''
                    /opt/sonar-scanner/bin/sonar-scanner \
                      -Dsonar.projectKey=demo-app \
                      -Dsonar.projectName="Demo App" \
                      -Dsonar.sources=. \
                      -Dsonar.host.url=${SONAR_HOST_URL} \
                      -Dsonar.login=${SONAR_AUTH_TOKEN}
                    '''
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                echo "🐳 Construction de l'image Docker..."
                sh '''
                docker build -t ${IMAGE_NAME}:${TAG} .
                '''
            }
        }

        stage('Trivy Scan') {
            steps {
                echo "🔍 Scan de l'image Docker avec Trivy..."
                sh '''
                trivy image --exit-code 0 --severity HIGH,CRITICAL ${IMAGE_NAME}:${TAG}
                '''
            }
        }
    }

    post {
        success {
            echo '✅ Pipeline terminé avec succès (SonarQube + Docker + Trivy).'
        }
        failure {
            echo '❌ Échec du pipeline (vérifie les logs).'
        }
        always {
            echo '🧹 Nettoyage des ressources...'
            sh 'docker image prune -f'
        }
    }
}
