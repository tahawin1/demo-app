pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube'
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
                    /opt/sonar-scanner/bin/sonar-scanner \
                      -Dsonar.projectKey=demo-app \
                      -Dsonar.projectName='Demo App' \
                      -Dsonar.sources=. \
                      -Dsonar.host.url=${SONAR_HOST_URL} \
                      -Dsonar.login=${SONAR_AUTH_TOKEN}
                    '''
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
