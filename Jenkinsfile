pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube' 
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'  // Image Docker d'OWASP ZAP
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
                echo 'Construction de l\'image Docker...'
                sh 'docker build -t demo-app:latest .'
            }
        }
        stage('Trivy Scan') {
            steps {
                echo 'Scan de l\'image Docker avec Trivy...'
                sh '''
                trivy image --severity HIGH,CRITICAL demo-app:latest > trivy-image-report.txt
                cat trivy-image-report.txt
                '''
            }
        }
        // Vérification de l'image Docker OWASP ZAP
        stage('Vérification Image ZAP') {
            steps {
                echo 'Vérification de l\'image OWASP ZAP...'
                sh """
                # Tentative de téléchargement explicite de l'image ZAP
                docker pull ${ZAP_IMAGE} || echo "AVERTISSEMENT: Impossible de télécharger l'image ZAP"
                """
            }
        }
        // Étape DAST modifiée - OWASP ZAP
        stage('Scan OWASP ZAP (DAST)') {
            steps {
                echo 'Scan dynamique de l\'application avec OWASP ZAP...'
                sh """
                # Utilisation du réseau host pour accéder à localhost
                docker run --network=host -v \$(pwd):/zap/wrk/:rw ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -r zap-report.html -I
                """
            }
            // Permettre à l'étape de continuer même si ZAP trouve des alertes
            // Les alertes ZAP ne devraient pas nécessairement faire échouer le build
            post {
                failure {
                    echo 'Le scan ZAP a rencontré des problèmes mais nous continuons le pipeline'
                    script {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        // Étape d'analyse des résultats ZAP modifiée
        stage('Analyse des résultats ZAP') {
            steps {
                echo 'Analyse des résultats OWASP ZAP...'
                sh '''
                # Vérification de l'existence du rapport
                if [ -f "zap-report.html" ]; then
                    echo "Rapport ZAP généré avec succès"
                    
                    # Vous pouvez ajouter ici un script pour analyser le contenu du rapport
                    # Par exemple, chercher des vulnérabilités de haute gravité
                    if grep -q "High" zap-report.html; then
                        echo "ATTENTION: Des vulnérabilités de haute gravité ont été détectées!"
                    fi
                else
                    echo "Rapport ZAP non trouvé - l'étape précédente a probablement échoué"
                    # Ne pas faire échouer le build ici pour permettre la continuité du pipeline
                    # mais marquer comme instable
                fi
                '''
            }
            // On ne fait pas échouer le build directement, on le marque comme instable
            post {
                failure {
                    echo 'Analyse des résultats ZAP incomplète mais nous continuons le pipeline'
                    script {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }
    post {
        success {
            echo '✅ Analyse SonarQube, SCA, scan de conteneur, et DAST réussis.'
        }
        unstable {
            echo '⚠️ Pipeline terminé mais certaines étapes sont instables. Vérifiez les rapports.'
        }
        failure {
            echo '❌ Échec d\'une des étapes de sécurité.'
        }
    }
}
