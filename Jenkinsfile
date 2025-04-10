pipeline {
    agent any

    environment {
        IMAGE_NAME = 'myapp'
        IMAGE_TAG = 'latest'
        DOCKER_REGISTRY = 'registry.example.com'
        SONARQUBE_SERVER = 'SonarQube' // Nom configuré dans Jenkins > Manage Jenkins > SonarQube servers
    }

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/mon-org/mon-projet.git'
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    docker.build("${IMAGE_NAME}:${IMAGE_TAG}")
                }
            }
        }

        stage('Trivy Scan') {
            steps {
                script {
                    sh """
                        trivy image --exit-code 1 --severity CRITICAL,HIGH ${IMAGE_NAME}:${IMAGE_TAG} > trivy-report.txt || true
                        cat trivy-report.txt
                    """
                }
            }
        }

        stage('SonarQube SAST Analysis') {
            steps {
                withSonarQubeEnv("${SONARQUBE_SERVER}") {
                    sh 'sonar-scanner -Dsonar.projectKey=myapp -Dsonar.sources=. -Dsonar.host.url=$SONAR_HOST_URL -Dsonar.login=$SONAR_AUTH_TOKEN'
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 1, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Push Docker Image') {
            steps {
                script {
                    docker.withRegistry("https://${DOCKER_REGISTRY}", 'docker-creds-id') {
                        docker.image("${IMAGE_NAME}:${IMAGE_TAG}").push()
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '**/trivy-report.txt', allowEmptyArchive: true
        }
    }
}
