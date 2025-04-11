pipeline {
    agent any

    environment {
        SONARQUBE_ENV = 'SonarQube' // 🔁 Remplace par le nom que tu as configuré dans Jenkins > Manage Jenkins > Configure System
    }

    stages {
        stage('Préparation') {
            steps {
                echo "📁 Clonage du projet..."
                git 'https://github.com/tahawin1/demo-app.git'
            }
        }

        stage('Analyse SonarQube') {
            steps {
                dir('sonar-scanning-examples/sonarqube-scanner') {
                             withSonarQubeEnv('SonarQube') {
    sh 'sonar-scanner'
}

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
