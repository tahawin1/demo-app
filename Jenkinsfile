pipeline {
    agent any
    
    environment {
        IMAGE_NAME = 'monapp'
        IMAGE_TAG = 'latest'
        SONARQUBE_ENV = 'SonarQube'
    }
    
    tools {
        // Assurez-vous que ce nom correspond exactement à celui configuré dans Jenkins
        sonarScanner 'SonarQube'
    }
    
    stages {
        stage('Execute') {
            steps {
                echo '🛠️ Exécution initiale...'
                sh 'echo "Commande exécutée avant build."'
            }
        }
        
        stage('Build') {
            steps {
                echo '📦 Construction de l\'image Docker...'
                sh 'docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .'
            }
        }
        
        stage('Test') {
            steps {
                echo '🧪 Exécution des tests...'
                sh 'echo "Tests exécutés (à remplacer par de vrais tests)"'
            }
        }
        
        stage('SonarQube Scan') {
            steps {
                echo '🔎 Analyse SonarQube (SAST)...'
                withSonarQubeEnv(credentialsId: "${SONARQUBE_ENV}") {
                    sh 'sonar-scanner'
                }
            }
        }
        
        stage('Scan') {
            steps {
                echo '🔍 Scan de sécurité avec Trivy...'
                sh 'trivy image --severity CRITICAL,HIGH ${IMAGE_NAME}:${IMAGE_TAG}'
            }
        }
        
        stage('Deploy') {
            steps {
                echo '🚀 Déploiement de l\'application...'
                sh 'docker rm -f monapp_container || true'
                sh 'docker run -d --name monapp_container -p 8080:80 ${IMAGE_NAME}:${IMAGE_TAG}'
            }
        }
    }
    
    post {
        success {
            echo 'Pipeline exécuté avec succès!'
        }
        failure {
            echo 'Le pipeline a échoué.'
        }
    }
}s
