pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube'
        // Ajout des variables d'environnement pour Cosign
        COSIGN_PRIVATE_KEY = credentials('cosign-key')
        COSIGN_PASSWORD = credentials('cosign-password')
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
                echo 'Construction de l'image Docker...'
                sh 'docker build -t demo-app:latest .'
            }
        }
        stage('Trivy Scan') {
            steps {
                echo 'Scan de l'image Docker avec Trivy...'
                sh '''
                trivy image --severity HIGH,CRITICAL demo-app:latest > trivy-image-report.txt
                cat trivy-image-report.txt
                '''
            }
        }
        // Nouvelle étape pour l'intégration de Cosign
        stage('Sign Docker Image with Cosign') {
            steps {
                echo 'Signature de l'image Docker avec Cosign...'
                // Installer Cosign si nécessaire (à commenter si Cosign est déjà installé)
                sh '''
                if ! command -v cosign &> /dev/null; then
                    echo "Installation de Cosign..."
                    curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
                    chmod +x cosign-linux-amd64
                    mv cosign-linux-amd64 /usr/local/bin/cosign
                fi
                '''
                
                // Signature de l'image avec la clé privée
                sh '''
                echo $COSIGN_PASSWORD | cosign sign --key $COSIGN_PRIVATE_KEY demo-app:latest
                '''
                
                // Vérification optionnelle de la signature
                sh '''
                cosign verify --key $COSIGN_PRIVATE_KEY.pub demo-app:latest
                '''
            }
        }
    }
    post {
        success {
            echo '✅ Analyse SonarQube, SCA, scan de conteneur et signature Cosign réussis.'
        }
        failure {
            echo '❌ Échec d'une des étapes de sécurité ou de signature.'
        }
    }
}
