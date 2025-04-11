pipeline {
    agent any

    environment {
        SONARQUBE_ENV = 'SonarQube' // même nom que dans "Configure System"
    }

    stages {
        stage('Cloner le code') {
            steps {
                git 'https://github.com/tahawin1/demo-app.git'
                dir('sonar-scanning-examples/sonarqube-scanner') {
                    echo 'Projet Sonar chargé.'
                }
            }
        }

        stage('Analyse SonarQube') {
            steps {
                dir('sonar-scanning-examples/sonarqube-scanner') {
                    withSonarQubeEnv("${sonarQube}") {
                        sh 'sonar-scanner'
                    }
                }
            }
        }

        stage('Vérification Quality Gate') {
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
            echo "✅ Analyse réussie et qualité conforme"
        }
        failure {
            echo "❌ Analyse échouée ou qualité non conforme"
        }
    }
}
