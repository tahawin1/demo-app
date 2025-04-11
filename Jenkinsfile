pipeline {
    agent any

    tools {
        // Adapte selon ton projet : maven / jdk / nodejs
        // example : maven 'Maven 3.8.5'
    }

    environment {
        SONARQUBE = 'SonarQube' // Le nom configuré dans Jenkins > SonarQube Servers
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app' // adapte le repo
            }
        }

        stage('Analyse SonarQube') {
            steps {
                withSonarQubeEnv("${sonarQube}") {
                    sh 'sonar-scanner'
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    timeout(time: 2, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: true
                    }
                }
            }
        }
    }

    post {
        success {
            echo '✅ Analyse SonarQube réussie et qualité validée.'
        }
        failure {
            echo '❌ Échec de l’analyse ou de la qualité SonarQube.'
        }
    }
}
