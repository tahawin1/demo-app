pipeline {
    agent any

    environment {
        IMAGE_NAME = "demo-app"
        TAG = "latest"
    }

    stages {
        stage('Checkout') {
            steps {
                git credentialsId: 'taaha', url: 'https://github.com/tahawin1/demo-app.git', branch: 'master'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${IMAGE_NAME}:${TAG} ."
            }
        }

        stage('Scan with Trivy') {
            steps {
                sh "trivy image --exit-code 0 --severity HIGH,CRITICAL ${IMAGE_NAME}:${TAG}"
            }
        }
    }

    post {
        always {
            echo 'Nettoyage des images non utilisées...'
            sh 'docker image prune -f'
        }
    }
}
