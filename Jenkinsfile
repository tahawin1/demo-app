pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube' 
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        TARGET_URL = 'http://demo.testfire.net'
        MISTRAL_API_KEY = credentials('taha-jenkins')
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
                script {
                    try {
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
                    } catch (Exception e) {
                        echo "Erreur lors de l'analyse SonarQube: ${e.message}"
                        echo "Continuons avec les autres étapes..."
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        stage('Analyse SCA - Dépendances') {
            steps {
                script {
                    try {
                        echo 'Analyse des dépendances (SCA) avec Trivy...'
                        sh '''
                        trivy fs --scanners vuln,license . > trivy-sca-report.txt || echo "Erreur lors du scan SCA" > trivy-sca-report.txt
                        cat trivy-sca-report.txt
                        '''
                    } catch (Exception e) {
                        echo "Erreur lors de l'analyse SCA: ${e.message}"
                        sh 'echo "Erreur lors du scan SCA" > trivy-sca-report.txt'
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        stage('Build Docker Image') {
            steps {
                script {
                    try {
                        echo 'Construction de l\'image Docker...'
                        sh 'docker build -t demo-app:latest . || exit 0'
                    } catch (Exception e) {
                        echo "Erreur lors du build Docker: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        stage('Trivy Scan') {
            steps {
                script {
                    try {
                        echo 'Scan de l\'image Docker avec Trivy...'
                        sh '''
                        trivy image --severity HIGH,CRITICAL demo-app:latest > trivy-image-report.txt || echo "Erreur lors du scan d'image" > trivy-image-report.txt
                        cat trivy-image-report.txt
                        '''
                    } catch (Exception e) {
                        echo "Erreur lors du scan Trivy: ${e.message}"
                        sh 'echo "Erreur lors du scan d\'image" > trivy-image-report.txt'
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        stage('Vérification Image ZAP') {
            steps {
                script {
                    try {
                        echo 'Vérification de l\'image OWASP ZAP...'
                        sh """
                        # Tentative de téléchargement explicite de l'image ZAP
                        docker pull ${ZAP_IMAGE} || echo "AVERTISSEMENT: Impossible de télécharger l'image ZAP"
                        """
                    } catch (Exception e) {
                        echo "Erreur lors de la vérification de l'image ZAP: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
                stage('Signer image avec Cosign') {
            steps {
                script {
                    try {
                        echo 'Signature de l\'image Docker avec Cosign...'
                        // Ajoute ton chemin de clé ou utilise un credential Jenkins
                        withCredentials([file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY')]) {
                            sh '''
                            export PATH=$HOME/bin:$PATH
                            cosign sign --key $COSIGN_KEY demo-app:latest
                            '''
                        }
                    } catch (Exception e) {
                        echo "Erreur lors de la signature Cosign: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Scan OWASP ZAP (DAST)') {
            steps {
                script {
                    try {
                        echo 'Scan dynamique de l\'application avec OWASP ZAP...'
                        // Capturer la sortie du scan ZAP pour avoir des informations en cas d'échec
                        def zapOutput = sh(script: """
                            mkdir -p zap-output
                            docker run --network=host -v \$(pwd):/zap/wrk/:rw ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -r zap-report.html -I > zap-output.log 2>&1 || true
                            # Vérifier si le rapport a été généré
                            if [ ! -f "zap-report.html" ]; then
                                # Si le rapport n'existe pas, extraire les alertes ZAP depuis la sortie
                                cat zap-output.log | grep -A 3 "WARN-NEW\\|FAIL-NEW" > zap-alerts.txt
                                # Créer un rapport HTML minimal
                                echo "<html><body><h1>ZAP Scan Results</h1><pre>" > zap-report.html
                                cat zap-alerts.txt >> zap-report.html
                                echo "</pre></body></html>" >> zap-report.html
                            fi
                            cat zap-output.log
                        """, returnStdout: true)
                        
                        echo "Résultat du scan ZAP:"
                        echo zapOutput
                        
                        // Copier le rapport avec un nom cohérent
                        sh 'cp zap-report.html zap-report1.html || touch zap-report1.html'
                    } catch (Exception e) {
                        echo "Erreur lors du scan ZAP: ${e.message}"
                        sh '''
                        # Créer un rapport HTML et un fichier d'alertes minimal en cas d'échec
                        echo "<html><body><h1>Scan ZAP non effectué</h1><p>Erreur lors de l'exécution du scan ZAP</p></body></html>" > zap-report.html
                        echo "<html><body><h1>Scan ZAP non effectué</h1><p>Erreur lors de l'exécution du scan ZAP</p></body></html>" > zap-report1.html
                        echo "Erreur lors du scan ZAP" > zap-alerts.txt
                        '''
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        stage('Analyse des résultats ZAP') {
            steps {
                script {
                    try {
                        echo 'Analyse des résultats OWASP ZAP...'
                        sh '''
                        # Assurons-nous que zap-alerts.txt existe
                        if [ ! -f "zap-alerts.txt" ]; then
                            # Si le fichier n'existe pas mais que le rapport existe
                            if [ -f "zap-report.html" ] || [ -f "zap-report1.html" ]; then
                                # Utiliser le rapport qui existe
                                REPORT_FILE=""
                                if [ -f "zap-report.html" ]; then
                                    REPORT_FILE="zap-report.html"
                                else
                                    REPORT_FILE="zap-report1.html"
                                fi
                                
                                # Extraire les alertes du rapport HTML
                                grep -A 5 "WARN-NEW\\|FAIL-NEW" $REPORT_FILE > zap-alerts.txt 2>/dev/null || echo "Extraction des alertes échouée"
                                
                                # Si l'extraction échoue, créer un fichier minimal
                                if [ ! -s "zap-alerts.txt" ]; then
                                    echo "Impossible d'extraire les alertes du rapport ZAP" > zap-alerts.txt
                                fi
                            else
                                # Ni rapport ni alertes n'existent
                                echo "Aucun rapport ZAP n'a été généré" > zap-alerts.txt
                            fi
                        fi
                        
                        # Afficher le contenu des alertes
                        echo "Contenu de zap-alerts.txt:"
                        cat zap-alerts.txt
                        
                        # Vérification des vulnérabilités critiques
                        if grep -q "FAIL-NEW\\|HIGH" zap-alerts.txt; then
                            echo "ATTENTION: Des vulnérabilités critiques ont été détectées!"
                        fi
                        '''
                    } catch (Exception e) {
                        echo "Erreur lors de l'analyse des résultats ZAP: ${e.message}"
                        sh 'echo "Erreur lors de l\'analyse des résultats ZAP" > zap-alerts.txt'
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        stage('Création du rapport combiné') {
            steps {
                script {
                    try {
                        echo 'Combinaison des rapports de sécurité...'
                        sh '''
                        # Création d'un répertoire pour les rapports
                        mkdir -p security-reports
                        
                        # Copie des rapports générés dans le répertoire
                        for report in trivy-sca-report.txt trivy-image-report.txt zap-report.html zap-report1.html zap-alerts.txt; do
                            if [ -f "$report" ]; then
                                cp "$report" security-reports/
                            fi
                        done
                        
                        # Création d'un rapport combiné pour Mistral AI
                        echo "# Rapport de sécurité combiné pour Demo App" > combined-security-report.txt
                        echo "## Date: $(date)" >> combined-security-report.txt
                        
                        # Section SCA
                        echo "\n## Rapport d'analyse des dépendances (Trivy SCA)" >> combined-security-report.txt
                        if [ -f "trivy-sca-report.txt" ]; then
                            cat trivy-sca-report.txt >> combined-security-report.txt
                        else
                            echo "Rapport SCA non disponible" >> combined-security-report.txt
                        fi
                        
                        # Section Image Docker
                        echo "\n## Rapport de scan d'image (Trivy)" >> combined-security-report.txt
                        if [ -f "trivy-image-report.txt" ]; then
                            cat trivy-image-report.txt >> combined-security-report.txt
                        else
                            echo "Rapport de scan d'image non disponible" >> combined-security-report.txt
                        fi
                        
                        # Section DAST/ZAP
                        echo "\n## Résultats principaux du scan DAST (ZAP)" >> combined-security-report.txt
                        if [ -f "zap-alerts.txt" ]; then
                            cat zap-alerts.txt >> combined-security-report.txt
                        else
                            echo "Résultats ZAP non disponibles" >> combined-security-report.txt
                        fi
                        
                        # État du pipeline
                        echo "\n## État du pipeline" >> combined-security-report.txt
                        if [ "${currentBuild.result}" == "UNSTABLE" ]; then
                            echo "⚠️ Certaines étapes du pipeline ont échoué ou sont instables" >> combined-security-report.txt
                        else
                            echo "✅ Toutes les étapes du pipeline ont été exécutées" >> combined-security-report.txt
                        fi
                        
                        echo "Rapport combiné créé: combined-security-report.txt"
                        '''
                    } catch (Exception e) {
                        echo "Erreur lors de la création du rapport combiné: ${e.message}"
                        sh '''
                        echo "# Rapport de sécurité combiné pour Demo App" > combined-security-report.txt
                        echo "## Date: $(date)" >> combined-security-report.txt
                        echo "\n⚠️ Erreur lors de la génération du rapport combiné" >> combined-security-report.txt
                        '''
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        stage('Consultation Mistral AI') {
            steps {
                script {
                    try {
                        echo 'Envoi des rapports à Mistral AI pour recommandations...'
                        
                        // Lecture du rapport combiné
                        def reportContent = ""
                        try {
                            reportContent = readFile('combined-security-report.txt')
                        } catch (Exception e) {
                            reportContent = "Aucun rapport n'a pu être généré lors du pipeline. Veuillez fournir des conseils généraux sur la sécurité des applications."
                        }
                        
                        // Créer un prompt nettoyé pour Mistral
                        def mistralPrompt = """En tant qu'expert en cybersécurité, analyse ce rapport de sécurité et fournit:
1. Un résumé des problèmes les plus critiques
2. Des recommandations précises pour résoudre chaque vulnérabilité importante
3. Des conseils pour améliorer le pipeline de sécurité
4. Des suggestions pour résoudre les problèmes techniques rencontrés (SonarQube inaccessible, problèmes de génération de rapports ZAP)

Voici le rapport:
${reportContent}"""

                        // Écrire le prompt dans un fichier temporaire
                        writeFile file: 'mistral-prompt.txt', text: mistralPrompt
                        
                        // Créer le JSON de manière plus sûre avec un script Python
                        writeFile file: 'create_mistral_request.py', text: '''
import json
import sys

with open('mistral-prompt.txt', 'r') as f:
    prompt = f.read()

request = {
    "model": "mistral-large-latest",
    "messages": [
        {
            "role": "user", 
            "content": prompt
        }
    ],
    "temperature": 0.2,
    "max_tokens": 4000
}

with open('mistral-request.json', 'w') as f:
    json.dump(request, f)
'''
                        
                        // Exécuter le script Python
                        sh 'python3 create_mistral_request.py'
                        
                        // Appel sécurisé à l'API Mistral avec gestion d'erreur avancée
                        def curlCommand = """
                        curl -s -X POST "${MISTRAL_API_URL}" \\
                        -H "Content-Type: application/json" \\
                        -H "Authorization: Bearer ${MISTRAL_API_KEY}" \\
                        -d @mistral-request.json > mistral-response.json || echo '{"error":"Erreur API"}' > mistral-response.json
                        """
                        
                        sh curlCommand
                        
                        // Extraction de la réponse avec Python pour plus de fiabilité
                        writeFile file: 'extract_response.py', text: '''
import json
import sys

try:
    with open('mistral-response.json', 'r') as f:
        response = json.load(f)
    
    if 'error' in response:
        print(f"Erreur lors de l'appel API Mistral: {response['error']}")
    elif 'choices' in response and len(response['choices']) > 0:
        if 'message' in response['choices'][0] and 'content' in response['choices'][0]['message']:
            print(response['choices'][0]['message']['content'])
        else:
            print("Structure de réponse incorrecte de Mistral AI")
    else:
        print("Aucune recommandation reçue de Mistral AI")
except Exception as e:
    print(f"Erreur lors du traitement de la réponse: {str(e)}")
    with open('mistral-response.json', 'r') as f:
        print(f"Réponse brute: {f.read()}")
'''
                        
                        // Exécuter l'extraction de la réponse
                        def recommendations = sh(script: 'python3 extract_response.py', returnStdout: true).trim()
                        
                        // Sauvegarde des recommandations
                        writeFile file: 'security-recommendations.md', text: recommendations
                        
                        echo "Recommandations de sécurité générées: security-recommendations.md"
                    } catch (Exception e) {
                        echo "Erreur lors de la consultation Mistral AI: ${e.message}"
                        writeFile file: 'security-recommendations.md', text: """# Erreur lors de la consultation Mistral AI

Une erreur s'est produite lors de la tentative de consultation de l'API Mistral AI:

${e.message}

## Conseils généraux de sécurité

En attendant de résoudre le problème d'API:

1. Vérifiez votre connexion Internet et les identifiants API
2. Assurez-vous que les rapports de sécurité sont générés correctement
3. Examinez manuellement les rapports de sécurité disponibles dans les artefacts du build
"""
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }
    post {
        success {
            echo '✅ Analyse et consultation IA réussis.'
            echo 'Les recommandations sont disponibles dans le fichier security-recommendations.md'
        }
        unstable {
            echo '⚠ Pipeline terminé mais certaines étapes sont instables. Vérifiez les rapports.'
        }
        failure {
            echo '❌ Échec critique du pipeline.'
        }
        always {
            // Archivage des rapports et recommandations comme artefacts
            archiveArtifacts artifacts: '*.txt, *.html, *.json, *.md, security-reports/*, zap-output.log', allowEmptyArchive: true
        }
    }
}
