pipeline {
    agent any

    environment {
        IMAGE_NAME = "demo-app"
        TAG = "latest"
    }

    tools {
        sonarScanner = 'SonarQubeScanner' // doit correspondre à ton nom dans Jenkins
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
                    sh 'sonar-scanner -Dsonar.projectKey=demo-app -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000 -Dsonar.login=<TOKEN>'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t $IMAGE_NAME:$TAG .'
            }
        }

        stage('Trivy Scan') {
            steps {
                sh 'trivy image --exit-code 0 --severity HIGH,CRITICAL $IMAGE_NAME:$TAG'
            }
        }
    }

    post {
        always {
            sh 'docker image prune -f'
        }
        failure {
            echo 'Le pipeline a échoué.'
        }
        success {
            echo 'Pipeline terminé avec succès !'
        }
    }
}
