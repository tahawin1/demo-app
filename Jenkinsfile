pipeline {
    agent any

    environment {
        IMAGE_NAME = "demo-app"
        TAG = "latest"
    }

    tools {
        // Assure-toi que "SonarQube Scanner" est configuré dans Jenkins global tools
        // Exemple dans Jenkins : Manage Jenkins > Global Tool Configuration > SonarQube Scanner
        sonarScanner = 'SonarQubeScanner'
    }

    stages {
        stage('Checkout') {
            steps {
                git credentialsId: 'taaha', url: 'https://github.com/tahawin1/demo-app.git', branch: 'master'
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner -Dsonar.projectKey=demo-app -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000 -Dsonar.java.binaries=.'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${IMAGE_NAME}:${TAG} ."
            }
        }

        stage('Trivy Scan') {
            steps {
                // Fait échouer le build si vulnérabilités HIGH ou CRITICAL
                sh "trivy image --exit-code 1 --severity HIGH,CRITICAL ${IMAGE_NAME}:${TAG}"
            }
        }
    }

    post {
        always {
            echo 'Nettoyage...'
            sh 'docker image prune -f'
        }
        success {
            echo '🎉 Pipeline terminé avec succès !'
        }
        failure {
            echo '❌ Échec du pipeline.'
        }
    }
}
