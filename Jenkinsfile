pipeline {
    agent any

    environment {
        IMAGE_NAME = 'monapp'
        IMAGE_TAG = 'latest'
        SONARQUBE_ENV = 'SonarQube'
    }

    tools {
        sonarScanner 'SonarQube'  // ← correspond exactement au nom défini dans ta capture
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
                sh 'docker build -t $IMAGE_NAME:$IMAGE_TAG .'
            }
        }

        stage('Test') {
            steps {
                echo '🧪 Exécution des tests...'
                // Exemple : Exécution d’un test basique
                sh 'echo "Tests exécutés (à remplacer par de vrais tests)"'
            }
        }

        stage('SonarQube Scan') {
            steps {
                echo '🔎 Analyse SonarQube (SAST)...'
                withSonarQubeEnv("${SONARQUBE_ENV}") {
                    sh 'sonar-scanner'
                }
            }
        }

        stage('Scan') {
            steps {
                echo '🔍 Scan de sécurité avec Trivy...'
                // Trivy doit être installé sur la machine Jenkins
                sh 'trivy image --severity CRITICAL,HIGH $IMAGE_NAME:$IMAGE_TAG'
            }
        }

        stage('Deploy') {
            steps {
                echo '🚀 Déploiement de l\'application...'
                // Supprimer le conteneur s’il existe déjà
                sh 'docker rm -f monapp_container || true'
                // Lancer l'image buildée
                sh 'docker run -d --name monapp_container -p 8080:80 $IMAGE_NAME:$IMAGE_TAG'
            }
        }
    }
}
