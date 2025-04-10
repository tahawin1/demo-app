pipeline {
    agent any

    environment {
        SONARQUBE_ENV = 'SonarQube' // nom dans Jenkins
        IMAGE_NAME = 'demo-app'
        IMAGE_TAG = 'latest'
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
                    sh 'sonar-scanner -Dsonar.projectKey=demo-app -Dsonar.sources=. -Dsonar.host.url=$SONAR_HOST_URL -Dsonar.login=$SONAR_AUTH_TOKEN'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
                }
            }
        }

        stage('Trivy Scan') {
            steps {
                script {
                    sh "trivy image --exit-code 1 --severity CRITICAL ${IMAGE_NAME}:${IMAGE_TAG} || echo 'Vulnérabilités détectées'"
                }
            }
        }

        // Optionnel : Signature Cosign (si activé)
        /*
        stage('Sign Docker Image') {
            steps {
                sh "cosign sign ${IMAGE_NAME}:${IMAGE_TAG}"
            }
        }
        */

        // Optionnel : Déploiement
        /*
        stage('Deploy') {
            steps {
                echo 'Déploiement en cours...'
            }
        }
        */
    }

    post {
        always {
            echo 'Pipeline terminé.'
            sh 'docker image prune -f'
        }
        failure {
            echo 'Le pipeline a échoué.'
        }
    }
}
