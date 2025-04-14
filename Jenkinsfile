pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube' 
        ZAP_IMAGE = 'owasp/zap2docker-stable'  // Image Docker d'OWASP ZAP
        TARGET_URL = 'http://localhost:8080'    // L'URL de l'application à scanner
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

        // ➕ Étape SCA - Analyse des dépendances avec Trivy
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

        // Nouvelle étape DAST - OWASP ZAP
        stage('Scan OWASP ZAP (DAST)') {
            steps {
                echo 'Scan dynamique de l\'application avec OWASP ZAP...'
                sh """
                docker run -v \$(pwd):/zap/wrk/:rw $ZAP_IMAGE zap-baseline.py -t $TARGET_URL
                """
            }
        }

        // Analyse des résultats de ZAP
        stage('Analyse des résultats ZAP') {
            steps {
                echo 'Analyse des résultats OWASP ZAP...'
                sh 'docker run -v $(pwd):/zap/wrk/:rw $ZAP_IMAGE zap-cli report -o owasp-zap-report.html'
                // Tu peux ajouter ici des scripts pour analyser le rapport et échouer le build si nécessaire
            }
        }
    }

    post {
        success {
            echo '✅ Analyse SonarQube, SCA, scan de conteneur, et DAST réussis.'
        }
        failure {
            echo '❌ Échec d’une des étapes de sécurité.'
        }
    }
}
