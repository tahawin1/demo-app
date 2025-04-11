pipeline {
    agent any
    environment {
        // Utiliser le nom exact tel qu'il apparaît dans la configuration Jenkins
        SONARQUBE_INSTALLATION = 'sonarQube'  // Exactement comme dans votre configuration
    }
    stages {
        stage('Checkout') {
            steps {
                echo "Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app'
            }
        }
        stage('Analyse SonarQube') {
            steps {
                withSonarQubeEnv("${SONARQUBE_INSTALLATION}") {
                    sh '''
                    sonar-scanner \
                      -Dsonar.projectKey=demo-app \
                      -Dsonar.projectName='Demo App' \
                      -Dsonar.sources=. \
                      -Dsonar.host.url=${SONAR_HOST_URL} \
                      -Dsonar.login=${SONAR_AUTH_TOKEN}
                    '''
                }
            }
        }
        stage('Quality Gate') {
            steps {
                timeout(time: 2, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }
    post {
        success {
            echo '✅ Analyse SonarQube réussie et qualité validée.'
        }
        failure {
            echo '❌ Échec de l\'analyse ou de la qualité SonarQube.'
        }
    }
}
