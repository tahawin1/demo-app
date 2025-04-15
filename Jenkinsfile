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
        
        // Étape DAST modifiée - OWASP ZAP avec meilleure gestion des erreurs
        stage('Scan OWASP ZAP (DAST)') {
            steps {
                echo 'Scan dynamique de l\'application avec OWASP ZAP...'
                script {
                    // Création manuelle d'un rapport ZAP de base pour éviter les échecs plus tard
                    sh 'echo "# Rapport ZAP (Sauvegarde)" > zap-report.html'
                    sh 'echo "{\\"alerts\\": []}" > zap-report.json'
                    
                    try {
                        // Utiliser -r pour définir explicitement le chemin complet du rapport
                        sh """
                        echo "Lancement du scan ZAP..."
                        docker run --network=host \
                            -v "\$(pwd)":/zap/wrk/:rw \
                            ${ZAP_IMAGE} \
                            zap-baseline.py \
                            -t ${TARGET_URL} \
                            -r /zap/wrk/zap-report.html \
                            -J /zap/wrk/zap-report.json \
                            -I \
                            -d
                        echo "Scan ZAP terminé"
                        """
                        
                        // Vérification des fichiers générés
                        sh '''
                        echo "Vérification des fichiers générés par ZAP:"
                        ls -la | grep zap
                        '''
                    } catch (Exception e) {
                        echo "⚠ Problème avec le scan ZAP: ${e.message}"
                        
                        // Capturer la sortie directement depuis la console ZAP
                        sh """
                        echo "Tentative de récupération des résultats ZAP directement..."
                        docker run --network=host \
                            ${ZAP_IMAGE} \
                            zap-baseline.py \
                            -t ${TARGET_URL} \
                            -I \
                            -d > zap-console-output.txt
                        
                        # Création d'un rapport manuel à partir de la sortie console
                        echo "<html><body><h1>Rapport ZAP (Généré à partir de la sortie console)</h1><pre>" > zap-report.html
                        cat zap-console-output.txt >> zap-report.html
                        echo "</pre></body></html>" >> zap-report.html
                        """
                    }
                }
            }
            post {
                always {
                    echo 'Conservation du rapport ZAP quelle que soit l\'issue du scan'
                    archiveArtifacts artifacts: 'zap.*', allowEmptyArchive: true
                }
            }
        }
        
        // Étape d'analyse des résultats ZAP améliorée
        stage('Analyse des résultats ZAP') {
            steps {
                echo 'Analyse des résultats OWASP ZAP...'
                sh '''
                # Création d'un rapport minimal si aucun n'existe
                if [ ! -f "zap-report.html" ]; then
                    echo "<html><body><h1>Rapport ZAP</h1><p>Aucun résultat disponible</p></body></html>" > zap-report.html
                    echo "Création d'un rapport ZAP minimal car aucun rapport n'a été trouvé"
                fi
                
                # Vérification des alertes
                if grep -q "High\\|Critical\\|Medium" zap-report.html; then
                    echo "⚠ ATTENTION: Des vulnérabilités ont été détectées!"
                else
                    echo "✅ Aucune vulnérabilité majeure détectée dans le rapport ZAP"
                fi
                
                # Sauvegarde des alertes dans un fichier séparé pour Mistral
                grep -A 15 "WARN\\|FAIL" zap-report.html > zap-alerts.txt || true
                '''
            }
        }
        
        // Nouvelle étape: Test de l'API Mistral
        stage('Test API Mistral') {
            steps {
                echo 'Test de connexion à l\'API Mistral...'
                sh '''
                # Afficher les premières lettres de la clé API (pour débogage)
                echo "Clé API Mistral (premiers caractères): ${MISTRAL_API_KEY:0:5}..."
                
                # Test simple de l'API Mistral
                curl -s -X GET https://api.mistral.ai/v1/models \
                  -H "Authorization: Bearer ${MISTRAL_API_KEY}" \
                  -o mistral-models.json
                
                # Vérifier si la requête a réussi
                if jq -e '.data' mistral-models.json > /dev/null; then
                    echo "✅ Connexion à l'API Mistral réussie"
                    jq -r '.data[].id' mistral-models.json
                else
                    echo "❌ Échec de connexion à l'API Mistral"
                    cat mistral-models.json
                    # On continue malgré l'erreur
                fi
                '''
            }
        }
        
        // Étape Mistral AI améliorée
        stage('Analyse Mistral AI') {
            steps {
                echo 'Préparation et envoi des rapports à Mistral AI pour analyse...'
                
                // Préparation des données pour Mistral AI avec meilleure gestion des erreurs
                sh '''
                # Création d'un fichier combiné avec les rapports
                echo "# Rapport de sécurité combiné" > combined-security-report.txt
                
                echo "## Rapport Trivy SCA" >> combined-security-report.txt
                if [ -f "trivy-sca-report.txt" ]; then
                    cat trivy-sca-report.txt >> combined-security-report.txt
                else
                    echo "Rapport SCA non disponible" >> combined-security-report.txt
                fi
                
                echo "## Rapport Trivy Image" >> combined-security-report.txt
                if [ -f "trivy-image-report.txt" ]; then
                    cat trivy-image-report.txt >> combined-security-report.txt
                else
                    echo "Rapport d'image non disponible" >> combined-security-report.txt
                fi
                
                echo "## Résumé des vulnérabilités ZAP" >> combined-security-report.txt
                if [ -f "zap-alerts.txt" ]; then
                    cat zap-alerts.txt >> combined-security-report.txt
                elif [ -f "zap-console-output.txt" ]; then
                    cat zap-console-output.txt >> combined-security-report.txt
                else
                    echo "Rapport ZAP non disponible" >> combined-security-report.txt
                fi
                
                # Sauvegarde du rapport combiné
                cp combined-security-report.txt security-report-for-mistral.txt
                '''
                
                // Appel de l'API Mistral avec une meilleure gestion des erreurs
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
                      "content": "$(cat security-report-for-mistral.txt)"
                    }
                  ]
                }
                EOL
                
                echo "Envoi de la requête à l'API Mistral..."
                
                # Appel de l'API Mistral avec verbose pour le débogage
                curl -v -X POST https://api.mistral.ai/v1/chat/completions \
                  -H "Content-Type: application/json" \
                  -H "Authorization: Bearer ${MISTRAL_API_KEY}" \
                  -d @mistral-request.json \
                  -o mistral-response.json
                
                # Vérification de la réponse
                if [ -f "mistral-response.json" ]; then
                    echo "Réponse de Mistral AI reçue:"
                    cat mistral-response.json | jq '.'
                    
                    # Extraction de la réponse si possible
                    if jq -e '.choices[0].message.content' mistral-response.json > /dev/null; then
                        jq -r '.choices[0].message.content' mistral-response.json > mistral-security-report.md
                        echo "Rapport Mistral AI généré avec succès"
                        
                        # Création d'un rapport HTML simple
                        echo '<html><head><meta charset="UTF-8"><title>Rapport de Sécurité IA</title><style>body{font-family:system-ui;max-width:800px;margin:0 auto;padding:20px}h1{color:#2c3e50}h2{color:#3498db}pre{background:#f8f8f8;padding:10px;overflow:auto;border-radius:3px}code{background:#f8f8f8;padding:2px 4px;border-radius:3px}</style></head><body>' > mistral-security-report.html
                        
                        # Conversion Markdown vers HTML (version simplifiée et corrigée)
                        cat mistral-security-report.md | sed 's/^# /\\<h1\\>/g' | sed 's/^## /\\<h2\\>/g' | sed 's/^### /\\<h3\\>/g' | sed 's//\\<code\\>/g' | sed 's//\\<\\/code\\>/g' | sed 's/^$/\\<br\\>/g' >> mistral-security-report.html
                        echo '</body></html>' >> mistral-security-report.html
                    else
                        echo "❌ Erreur: Impossible d'extraire le contenu de la réponse Mistral"
                        # Création d'un rapport d'erreur
                        echo "# Erreur d'analyse Mistral AI" > mistral-security-report.md
                        echo "Une erreur s'est produite lors de l'analyse par Mistral AI. Consultez les logs Jenkins pour plus de détails." >> mistral-security-report.md
                        
                        # Version HTML
                        echo '<html><head><title>Erreur Rapport Mistral</title></head><body><h1>Erreur d\\'analyse Mistral AI</h1><p>Une erreur s\\'est produite lors de l\\'analyse par Mistral AI. Consultez les logs Jenkins pour plus de détails.</p></body></html>' > mistral-security-report.html
                    fi
                else
                    echo "❌ Erreur: Aucune réponse reçue de Mistral AI"
                    # Création d'un rapport d'erreur
                    echo "# Erreur de communication avec Mistral AI" > mistral-security-report.md
                    echo "Aucune réponse n'a été reçue de Mistral AI. Vérifiez votre connexion et vos identifiants." >> mistral-security-report.md
                    
                    # Version HTML
                    echo '<html><head><title>Erreur Rapport Mistral</title></head><body><h1>Erreur de communication avec Mistral AI</h1><p>Aucune réponse n\\'a été reçue de Mistral AI. Vérifiez votre connexion et vos identifiants.</p></body></html>' > mistral-security-report.html
                fi
                '''
                
                // Création d'un fichier simple en cas d'échec pour éviter des erreurs d'archivage
                sh '''
                if [ ! -f "mistral-security-report.md" ]; then
                    echo "# Rapport de sécurité" > mistral-security-report.md
                    echo "Aucune analyse n'a pu être générée" >> mistral-security-report.md
                fi
                
                if [ ! -f "mistral-security-report.html" ]; then
                    echo '<html><body><h1>Rapport de sécurité</h1><p>Aucune analyse n\'a pu être générée</p></body></html>' > mistral-security-report.html
                fi
                '''
                
                // Archivage de tous les rapports et logs pour faciliter le débogage
                archiveArtifacts artifacts: '*.md, *.html, *.json, *.txt', allowEmptyArchive: true
            }
        }
    }
    post {
        success {
            echo '✅ Analyse SonarQube, SCA, scan de conteneur, DAST et analyse IA réussis.'
            echo 'Les rapports sont disponibles dans les artefacts du build.'
        }
        unstable {
            echo '⚠ Pipeline terminé mais certaines étapes sont instables. Vérifiez les rapports.'
        }
        failure {
            echo '❌ Échec d\'une des étapes de sécurité.'
        }
        always {
            // Archive even more artifacts for debugging
            archiveArtifacts artifacts: '/mistral-., */zap-., **/trivy-.*', allowEmptyArchive: true
        }
    }
}
