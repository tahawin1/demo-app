pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube' 
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'  // Image Docker d'OWASP ZAP
        TARGET_URL = 'http://localhost:8080'    // L'URL de l'application à scanner
        MISTRAL_API_KEY = credentials('taha-jenkins') // Credentials Jenkins pour l'API Mistral
    }
    stages {
        // Nouvelle étape: Installation des outils requis
        stage('Install Requirements') {
            steps {
                echo 'Installation des outils requis (jq et curl)...'
                script {
                    def osType = sh(script: 'uname -s', returnStdout: true).trim()
                    
                    // Vérification et installation de jq
                    if (sh(script: 'which jq', returnStatus: true) != 0) {
                        echo 'Installation de jq...'
                        if (osType == 'Linux') {
                            // Détection de la distribution
                            if (sh(script: 'test -f /etc/debian_version', returnStatus: true) == 0) {
                                sh 'apt-get update && apt-get install -y jq'
                            } else if (sh(script: 'test -f /etc/redhat-release', returnStatus: true) == 0) {
                                sh 'yum install -y jq'
                            } else if (sh(script: 'which apk', returnStatus: true) == 0) {
                                sh 'apk add --no-cache jq'
                            } else {
                                error "Distribution Linux non prise en charge pour l'installation automatique de jq. Veuillez l'installer manuellement."
                            }
                        } else {
                            error "Système d'exploitation non pris en charge pour l'installation automatique de jq. Veuillez l'installer manuellement."
                        }
                    } else {
                        echo 'jq est déjà installé'
                    }
                    
                    // Vérification et installation de curl
                    if (sh(script: 'which curl', returnStatus: true) != 0) {
                        echo 'Installation de curl...'
                        if (osType == 'Linux') {
                            if (sh(script: 'test -f /etc/debian_version', returnStatus: true) == 0) {
                                sh 'apt-get update && apt-get install -y curl'
                            } else if (sh(script: 'test -f /etc/redhat-release', returnStatus: true) == 0) {
                                sh 'yum install -y curl'
                            } else if (sh(script: 'which apk', returnStatus: true) == 0) {
                                sh 'apk add --no-cache curl'
                            } else {
                                error "Distribution Linux non prise en charge pour l'installation automatique de curl. Veuillez l'installer manuellement."
                            }
                        } else {
                            error "Système d'exploitation non pris en charge pour l'installation automatique de curl. Veuillez l'installer manuellement."
                        }
                    } else {
                        echo 'curl est déjà installé'
                    }
                }
            }
        }

        // Verification des outils installés
        stage('Verify Tools') {
            steps {
                echo 'Vérification des outils installés...'
                sh 'which jq && jq --version'
                sh 'which curl && curl --version'
            }
        }
        
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
                # Utilisation du format JSON pour une meilleure intégration avec l'API
                trivy image --format json --severity HIGH,CRITICAL demo-app:latest > trivy-image-report.json
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
                docker run --network=host -v \$(pwd):/zap/wrk/:rw ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -r zap-report.html -I -J zap-report.json
                """
            }
            // Permettre à l'étape de continuer même si ZAP trouve des alertes
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
                fi
                '''
            }
            post {
                failure {
                    echo 'Analyse des résultats ZAP incomplète mais nous continuons le pipeline'
                    script {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        // Nouvelle étape: Envoi des rapports à Mistral AI et génération du rapport d'amélioration
        stage('Analyse Mistral AI') {
            steps {
                echo 'Envoi des rapports à Mistral AI pour analyse...'
                
                // Préparation des données pour Mistral AI
                sh '''
                # Création d'un fichier combiné avec les rapports
                echo "# Rapport Trivy SCA" > combined-security-report.txt
                cat trivy-sca-report.txt >> combined-security-report.txt
                echo "\\n\\n# Rapport Trivy Image" >> combined-security-report.txt
                cat trivy-image-report.txt >> combined-security-report.txt
                echo "\\n\\n# Résumé des vulnérabilités ZAP" >> combined-security-report.txt
                
                # Extraction des informations clés du rapport ZAP HTML
                if [ -f "zap-report.html" ]; then
                    # Extraire les alertes du HTML (version simplifiée)
                    grep -A 5 "alert" zap-report.html >> combined-security-report.txt
                else
                    echo "Rapport ZAP non disponible" >> combined-security-report.txt
                fi
                '''
                
                // Appel de l'API Mistral en utilisant curl
                sh '''
                # Création du contenu de la requête
                cat > mistral-request.json << EOL
                {
                  "model": "mistral-large-latest",
                  "messages": [
                    {
                      "role": "system",
                      "content": "Tu es un expert en cybersécurité spécialisé dans l'analyse de vulnérabilités. Analyse les rapports de sécurité fournis (Trivy SCA, Trivy Image et OWASP ZAP) et génère un rapport détaillé avec: 1) Résumé des vulnérabilités critiques et élevées, 2) Recommandations concrètes pour résoudre chaque vulnérabilité, 3) Priorités d'action, 4) Suggestions d'amélioration de l'architecture. Organise le rapport de manière claire et fournit des instructions précises."
                    },
                    {
                      "role": "user",
                      "content": "$(cat combined-security-report.txt)"
                    }
                  ]
                }
                EOL
                
                # Appel de l'API Mistral
                curl -s -X POST https://api.mistral.ai/v1/chat/completions \
                  -H "Content-Type: application/json" \
                  -H "Authorization: Bearer ${MISTRAL_API_KEY}" \
                  -d @mistral-request.json \
                  -o mistral-response.json
                
                # Extraction de la réponse
                cat mistral-response.json | jq -r '.choices[0].message.content' > mistral-security-report.md
                
                # Conversion en HTML pour une meilleure visualisation
                echo '<html><head><meta charset="UTF-8"><title>Rapport de Sécurité IA</title><style>body{font-family:system-ui;max-width:800px;margin:0 auto;padding:20px}h1{color:#2c3e50}h2{color:#3498db}pre{background:#f8f8f8;padding:10px;overflow:auto;border-radius:3px}code{background:#f8f8f8;padding:2px 4px;border-radius:3px}</style></head><body>' > mistral-security-report.html
                
                # Conversion Markdown vers HTML (version simplifiée)
                cat mistral-security-report.md | sed 's/^# /\\<h1\\>/g' | sed 's/^## /\\<h2\\>/g' | sed 's/^### /\\<h3\\>/g' | sed 's//\\<code\\>/g' | sed 's//\\<\\/code\\>/g' | sed 's/^$/\\<br\\>/g' >> mistral-security-report.html
                echo '</body></html>' >> mistral-security-report.html
                '''
                
                // Archivage du rapport
                archiveArtifacts artifacts: 'mistral-security-report.*', allowEmptyArchive: true
            }
        }
    }
    post {
        success {
            echo '✅ Analyse SonarQube, SCA, scan de conteneur, DAST et analyse IA réussis.'
            echo 'Le rapport Mistral AI est disponible dans les artefacts du build.'
        }
        unstable {
            echo '⚠ Pipeline terminé mais certaines étapes sont instables. Vérifiez les rapports.'
        }
        failure {
            echo '❌ Échec d\'une des étapes de sécurité.'
        }
    }
}
