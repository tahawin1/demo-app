pipeline {
    agent any

    environment {
        IMAGE_NAME = 'monapp'
        IMAGE_TAG = 'latest'
    }

    stages {
        stage('Build') {
            steps {
                echo '📦 Building the application...'
                sh 'docker build -t $IMAGE_NAME:$IMAGE_TAG .'
            }
        }

        stage('Trivy Scan') {
            steps {
                echo '🔍 Scanning Docker image with Trivy...'
                // Assure-toi que Trivy est installé sur ta machine Jenkins
                sh 'trivy image --severity CRITICAL,HIGH $IMAGE_NAME:$IMAGE_TAG'
            }
        }

        stage('Test') {
            steps {
                echo '🧪 Testing the application...'
                // Ajoute tes tests ici si nécessaire
            }
        }

        stage('Deploy') {
            steps {
                echo '🚀 Deploying the application...'
                // Ici tu peux pousser ton image ou lancer un conteneur
                // Exemple simple :
                sh 'docker run -d --rm --name monapp
