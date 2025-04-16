pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube' 
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        TARGET_URL = 'http://demo.testfire.net'
        MISTRAL_API_KEY = credentials('taha-jenkins') // Créez cette credential dans Jenkins
        MISTRAL_API_URL = 'https://api.mistral.ai/v1/chat/completions'
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
        stage('Vérification Image ZAP') {
            steps {
                echo 'Vérification de l\'image OWASP ZAP...'
                sh """
                # Tentative de téléchargement explicite de l'image ZAP
                docker pull ${ZAP_IMAGE} || echo "AVERTISSEMENT: Impossible de télécharger l'image ZAP"
                """
            }
        }
        stage('Scan OWASP ZAP (DAST)') {
            steps {
                echo 'Scan dynamique de l\'application avec OWASP ZAP...'
                sh """
                # Utilisation du réseau host pour accéder à localhost
                docker run --network=host -v \$(pwd):/zap/wrk/:rw ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -r zap-report1.html -I
                """
            }
            post {
                failure {
                    echo 'Le scan ZAP a rencontré des problèmes mais nous continuons le pipeline'
                    script {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        stage('Analyse des résultats ZAP') {
            steps {
                echo 'Analyse des résultats OWASP ZAP...'
                sh '''
                # Vérification de l'existence du rapport
                if [ -f "zap-report1.html" ]; then
                    echo "Rapport ZAP généré avec succès"
                    
                    # Vous pouvez ajouter ici un script pour analyser le contenu du rapport
                    # Par exemple, chercher des vulnérabilités de haute gravité
                    if grep -q "High" zap-report1.html; then
                        echo "ATTENTION: Des vulnérabilités de haute gravité ont été détectées!"
                    fi
                else
                    echo "Rapport ZAP non trouvé - l'étape précédente a probablement échoué"
                    # Ne pas faire échouer le build ici pour permettre la continuité du pipeline
                    # mais marquer comme instable
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
        
        // Nouvelle étape pour combiner les rapports et les envoyer à Mistral AI
        stage('Création du rapport combiné') {
            steps {
                echo 'Combinaison des rapports de sécurité...'
                sh '''
                # Création d'un répertoire pour les rapports
                mkdir -p security-reports
                
                # Copie des rapports générés
                [ -f "trivy-sca-report.txt" ] && cp trivy-sca-report.txt security-reports/ || echo "Rapport SCA non trouvé"
                [ -f "trivy-image-report.txt" ] && cp trivy-image-report.txt security-reports/ || echo "Rapport image non trouvé"
                [ -f "zap-report1.html" ] && cp zap-report1.html security-reports/ || echo "Rapport ZAP HTML non trouvé"
                
                # Création d'un rapport combiné pour Mistral AI
                echo "# Rapport de sécurité combiné pour Demo App" > combined-security-report.txt
                echo "## Date: $(date)" >> combined-security-report.txt
                echo "\n## Rapport d'analyse des dépendances (Trivy SCA)" >> combined-security-report.txt
                [ -f "trivy-sca-report.txt" ] && cat trivy-sca-report.txt >> combined-security-report.txt || echo "Non disponible" >> combined-security-report.txt
                echo "\n## Rapport de scan d'image (Trivy)" >> combined-security-report.txt
                [ -f "trivy-image-report.txt" ] && cat trivy-image-report.txt >> combined-security-report.txt || echo "Non disponible" >> combined-security-report.txt
                echo "\n## Résultats principaux du scan DAST (ZAP)" >> combined-security-report.txt
                [ -f "zap-alerts.txt" ] && cat zap-alerts.txt >> combined-security-report.txt || echo "Non disponible" >> combined-security-report.txt
                
                # Extraire les alertes ZAP du HTML (simplifié)
                if [ -f "zap-report1.html" ]; then
                    grep -A 5 "alert" zap-report1.html | head -50 > zap-alerts.txt
                    cat zap-alerts.txt >> combined-security-report.txt
                fi
                
                echo "Rapport combiné créé: combined-security-report.txt"
                '''
            }
        }
        
        stage('Consultation Mistral AI') {
            steps {
                echo 'Envoi des rapports à Mistral AI pour recommandations...'
                script {
                    // Construction de la requête pour Mistral AI
                    def reportContent = readFile('combined-security-report.txt')
                    
                    def mistralPrompt = """En tant qu'expert en cybersécurité, analyse ce rapport de sécurité et fournit:
1. Un résumé des problèmes les plus critiques
2. Des recommandations précises pour résoudre chaque vulnérabilité importante
3. Des conseils pour améliorer le pipeline de sécurité

Voici le rapport:
${reportContent}"""
                    
                    // Création du JSON pour l'API Mistral
                    def mistralRequest = """
{
    "model": "mistral-large-latest",
    "messages": [
        {
            "role": "user",
            "content": "${mistralPrompt.replaceAll('"', '\\\\"').replaceAll('\n', '\\\\n')}"
        }
    ],
    "temperature": 0.2,
    "max_tokens": 4000
}"""
                    
                    // Écriture de la requête dans un fichier pour debug et historique
                    writeFile file: 'mistral-request.json', text: mistralRequest
                    
                    // Appel de l'API Mistral
                    def mistralResponse = sh(script: """
                        curl -s -X POST ${MISTRAL_API_URL} \\
                        -H "Content-Type: application/json" \\
                        -H "Authorization: Bearer ${MISTRAL_API_KEY}" \\
                        -d @mistral-request.json
                    """, returnStdout: true).trim()
                    
                    // Extraction de la réponse (à adapter selon le format exact de réponse Mistral)
                    // Cette ligne utilise jq pour extraire la première réponse du modèle
                    // Installez jq dans votre image Jenkins
                    def recommendations = sh(script: """
                        echo '${mistralResponse}' | jq -r '.choices[0].message.content'
                    """, returnStdout: true).trim()
                    
                    // Sauvegarde des recommandations
                    writeFile file: 'security-recommendations.md', text: recommendations
                    
                    echo "Recommandations de sécurité générées: security-recommendations.md"
                }
            }
        }
    }
    post {
        success {
            echo '✅ Analyse SonarQube, SCA, scan de conteneur, DAST et consultation IA réussis.'
            echo 'Les recommandations sont disponibles dans le fichier security-recommendations.md'
        }
        unstable {
            echo '⚠ Pipeline terminé mais certaines étapes sont instables. Vérifiez les rapports.'
        }
        failure {
            echo '❌ Échec d\'une des étapes de sécurité.'
        }
        always {
            // Archivage des rapports et recommandations comme artefacts
            archiveArtifacts artifacts: '*report*.txt, *report*.html, *report*.json, security-recommendations.md, combined-security-report.txt', allowEmptyArchive: true
        }
    }
}
