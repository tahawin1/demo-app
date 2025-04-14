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

        stage('Analyse SCA - Dépendances') {
            steps {
                echo 'Analyse des dépendances (SCA) avec Trivy...'
                sh '''
                trivy fs --scanners vuln,license . > trivy-sca-report.txt
                cat trivy-sca-report.txt
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                echo 'Construction de l’image Docker...'
                sh 'docker build -t demo-app:latest .'
            }
        }

        stage('Trivy Scan') {
            steps {
                echo 'Scan de l’image Docker avec Trivy...'
                sh '''
                trivy image --severity HIGH,CRITICAL demo-app:latest > trivy-image-report.txt
                cat trivy-image-report.txt
                '''
            }
        }

        stage('Cosign Sign Image') {
            steps {
                echo 'Signature de l’image Docker avec Cosign...'
                withCredentials([file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY')]) {
                    sh '''
                    cosign sign --key $COSIGN_KEY demo-app:latest
                    '''
                }
            }
        }
    }

    post {
        success {
            echo '✅ Analyse SonarQube, SCA, scan de conteneur et signature réussis.'
        }
        failure {
            echo '❌ Échec d’une des étapes de sécurité.'
        }
    }
}
