pipeline {
    agent any
    environment {
        SONARQUBE_INSTALLATION = 'sonarQube'
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        TARGET_URL = 'http://testphp.vulnweb.com'

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
                              -Dsonar.host.url=$SONAR_HOST_URL \
                              -Dsonar.login=$SONAR_AUTH_TOKEN
                            '''
                        }
                    } catch (Exception e) {
                        echo "Erreur SonarQube: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Analyse SCA - Trivy (Dépendances)') {
            steps {
                script {
                    try {
                        echo 'Analyse SCA avec Trivy...'
                        sh '''
                        trivy fs --scanners vuln,license . > trivy-sca-report.txt || echo "Erreur scan SCA" > trivy-sca-report.txt
                        '''
                    } catch (Exception e) {
                        echo "Erreur SCA: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    try {
                        echo 'Construction de l’image Docker...'
                        sh 'docker build -t demo-app:latest .'
                    } catch (Exception e) {
                        echo "Erreur build Docker: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Scan Image avec Trivy') {
            steps {
                script {
                    try {
                        echo 'Scan image Docker avec Trivy...'
                        sh '''
                        trivy image --severity HIGH,CRITICAL demo-app:latest > trivy-image-report.txt || echo "Erreur scan image" > trivy-image-report.txt
                        '''
                    } catch (Exception e) {
                        echo "Erreur Trivy image: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Pull Image OWASP ZAP') {
            steps {
                script {
                    try {
                        echo 'Téléchargement de l’image OWASP ZAP...'
                        sh 'docker pull ${ZAP_IMAGE}'
                    } catch (Exception e) {
                        echo "Erreur téléchargement ZAP: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Scan DAST avec ZAP') {
            steps {
                script {
                    try {
                        echo 'Scan ZAP en cours...'
                        sh '''
                        mkdir -p zap-output
                        docker run --network=host -v $(pwd):/zap/wrk/:rw ${ZAP_IMAGE} \
                        zap-baseline.py -t ${TARGET_URL} -r zap-report.html -I > zap-output.log 2>&1 || true
                        
                        if [ ! -f "zap-report.html" ]; then
                            grep -A 3 "WARN-NEW\\|FAIL-NEW" zap-output.log > zap-alerts.txt
                            echo "<html><body><h1>Résultats ZAP</h1><pre>" > zap-report.html
                            cat zap-alerts.txt >> zap-report.html
                            echo "</pre></body></html>" >> zap-report.html
                        fi
                        cp zap-report.html zap-report1.html || touch zap-report1.html
                        '''
                    } catch (Exception e) {
                        echo "Erreur scan ZAP: ${e.message}"
                        sh '''
                        echo "<html><body><h1>Échec scan ZAP</h1></body></html>" > zap-report.html
                        cp zap-report.html zap-report1.html
                        echo "Erreur scan ZAP" > zap-alerts.txt
                        '''
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Analyse Résultats ZAP') {
            steps {
                script {
                    try {
                        echo 'Analyse des alertes ZAP...'
                        sh '''
                        if [ ! -f "zap-alerts.txt" ]; then
                            grep -A 5 "WARN-NEW\\|FAIL-NEW" zap-report.html > zap-alerts.txt || echo "Pas d’alertes détectées"
                        fi

                        echo "Contenu zap-alerts.txt:"
                        cat zap-alerts.txt
                        '''
                    } catch (Exception e) {
                        echo "Erreur analyse ZAP: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Création Rapport Combiné') {
            steps {
                script {
                    try {
                        echo 'Création du rapport global...'
                        sh '''
                        mkdir -p security-reports

                        for f in trivy-*.txt zap-*.html zap-alerts.txt; do
                            [ -f "$f" ] && cp "$f" security-reports/
                        done

                        echo "# Rapport sécurité Demo App" > combined-security-report.txt
                        echo "## Date: $(date)" >> combined-security-report.txt

                        echo "\n## Analyse SCA" >> combined-security-report.txt
                        cat trivy-sca-report.txt >> combined-security-report.txt || echo "Non dispo" >> combined-security-report.txt

                        echo "\n## Scan image Docker" >> combined-security-report.txt
                        cat trivy-image-report.txt >> combined-security-report.txt || echo "Non dispo" >> combined-security-report.txt

                        echo "\n## Scan DAST (ZAP)" >> combined-security-report.txt
                        cat zap-alerts.txt >> combined-security-report.txt || echo "Non dispo" >> combined-security-report.txt
                        '''
                    } catch (Exception e) {
                        echo "Erreur création rapport combiné: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Consultation Mistral AI') {
            steps {
                script {
                    try {
                        echo 'Envoi du rapport à Mistral AI...'
                        def reportContent = readFile('combined-security-report.txt')

                        def mistralPrompt = """En tant qu'expert sécurité, analyse ce rapport :
1. Résume les problèmes critiques
2. Donne des solutions précises
3. Donne des conseils sur le pipeline DevSecOps
Voici le rapport :
${reportContent}
"""

                        writeFile file: 'mistral-prompt.txt', text: mistralPrompt
                        writeFile file: 'create_request.py', text: '''
import json
prompt = open('mistral-prompt.txt').read()
with open('mistral-request.json', 'w') as f:
    json.dump({
        "model": "mistral-large-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 4000
    }, f)
'''
                        sh 'python3 create_request.py'

                        sh '''
                        curl -s -X POST "${MISTRAL_API_URL}" \
                        -H "Content-Type: application/json" \
                        -H "Authorization: Bearer ${MISTRAL_API_KEY}" \
                        -d @mistral-request.json > mistral-response.json || echo '{"error":"Erreur"}' > mistral-response.json
                        '''

                        writeFile file: 'extract_response.py', text: '''
import json
data = json.load(open("mistral-response.json"))
if "choices" in data:
    print(data["choices"][0]["message"]["content"])
else:
    print("Aucune réponse valide.")
'''
                        def recommendations = sh(script: 'python3 extract_response.py', returnStdout: true).trim()
                        writeFile file: 'security-recommendations.md', text: recommendations

                        echo "✅ Recommandations générées avec succès !"
                    } catch (Exception e) {
                        echo "Erreur Mistral: ${e.message}"
                        writeFile file: 'security-recommendations.md', text: "Erreur lors de la consultation de Mistral AI."
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }

    post {
        success {
            echo '✅ Pipeline terminé avec succès.'
        }
        unstable {
            echo '⚠ Pipeline terminé avec avertissements.'
        }
        failure {
            echo '❌ Pipeline échoué.'
        }
        always {
            archiveArtifacts artifacts: '*.txt,*.html,*.json,*.md,security-reports/*,zap-output.log', allowEmptyArchive: true
        }
    }
}
