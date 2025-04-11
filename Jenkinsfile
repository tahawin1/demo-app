pipeline {
    agent any

    environment {
        SONARQUBE_ENV = 'SonarQube' // 🔁 Remplace par le nom que tu as configuré dans Jenkins > Manage Jenkins > Configure System
    }

    stages {
        stage('Préparation') {
            steps {
                echo "📁 Clonage du projet..."
                git 'https://github.com/SonarSource/sonar-scanning-examples.git'
            }
        }

        stage('Analyse SonarQube') {
            steps {
                dir('sonar-scanning-examples/sonarqube-scanner') {
                    withSonarQubeEnv("${SONARQUBE_ENV}") {
                        echo "🚀 Analyse avec SonarScanner"
                        sh 'sonar-scanner -X'
                    }
                }
            }
        }

        stage('Vérification Quality Gate') {
            steps {
                script {
                    timeout(time: 3, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: true
                    }
                }
            }
        }
    }

    post {
        success {
            echo "✅ Analyse et Quality Gate validés"
        }
        failure {
            echo "❌ Échec : Analyse ou Quality Gate"
        }
    }
}
