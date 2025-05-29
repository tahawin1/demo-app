pipeline {
    agent any
    environment {
        // 🔧 VOS CONFIGURATIONS ORIGINALES
        SONARQUBE_INSTALLATION = 'sonarQube' 
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        TARGET_URL = 'http://demo.testfire.net'
        MISTRAL_API_KEY = credentials('taha-jenkins')
        MISTRAL_API_URL = 'https://api.mistral.ai/v1/chat/completions'
        
        // 🆕 NOUVELLES CONFIGURATIONS KUBERNETES
        APP_NAME = "${env.JOB_NAME}-${env.BUILD_NUMBER}".toLowerCase().replaceAll(/[^a-z0-9-]/, '-')
        IMAGE_NAME = "demo-app"
        K8S_NAMESPACE = "secure-namespace"
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo "Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app'
                
                // 🆕 Vérifier les nouveaux dossiers
                sh '''
                    mkdir -p k8s-deploy security-reports
                    echo "📋 Structure du projet:"
                    ls -la
                    if [ -d "k8s-templates" ]; then
                        echo "✅ Templates K8s trouvés:"
                        ls -la k8s-templates/
                    fi
                '''
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
        
        // 🆕 NOUVELLE ÉTAPE: Génération manifests K8s (si templates existent)
        stage('🛡️ Generate Kubernetes Manifests') {
            when {
                expression { fileExists('k8s-templates/secure-deployment.yaml') }
            }
            steps {
                script {
                    echo "🔧 Génération des manifests Kubernetes sécurisés..."
                    try {
                        sh '''
                            echo "📋 Variables pour substitution:"
                            echo "APP_NAME: ${APP_NAME}"
                            echo "BUILD_NUMBER: ${BUILD_NUMBER}"
                            echo "IMAGE_NAME: ${IMAGE_NAME}"
                            
                            # Générer les manifests
                            envsubst < k8s-templates/secure-deployment.yaml > k8s-deploy/deployment.yaml
                            envsubst < k8s-templates/secure-service.yaml > k8s-deploy/service.yaml 2>/dev/null || echo "Service template non trouvé"
                            envsubst < k8s-templates/networkpolicy.yaml > k8s-deploy/networkpolicy.yaml 2>/dev/null || echo "NetworkPolicy template non trouvé"
                            envsubst < k8s-templates/rbac.yaml > k8s-deploy/rbac.yaml 2>/dev/null || echo "RBAC template non trouvé"
                            
                            echo "✅ Manifests générés:"
                            ls -la k8s-deploy/
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Erreur génération manifests: ${e.message}"
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
                        
                        // 🆕 Scan des configurations K8s si elles existent
                        sh '''
                        if [ -d "k8s-deploy" ] && [ "$(ls -A k8s-deploy)" ]; then
                            echo "🔍 Scan des configurations Kubernetes..."
                            trivy config k8s-deploy/ > trivy-k8s-report.txt || echo "Pas de scan K8s" > trivy-k8s-report.txt
                            cat trivy-k8s-report.txt
                        fi
                        '''
                    } catch (Exception e) {
                        echo "Erreur lors du scan Trivy: ${e.message}"
                        sh 'echo "Erreur lors du scan d\'image" > trivy-image-report.txt'
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        // 🆕 Tests de sécurité K8s (si script existe)
        stage('🧪 Kubernetes Security Tests') {
            when {
                expression { fileExists('scripts/validate-k8s-security.sh') }
            }
            steps {
                script {
                    try {
                        echo '🧪 Tests de sécurité Kubernetes (simulation)...'
                        sh '''
                            chmod +x scripts/validate-k8s-security.sh
                            
                            echo "🛡️ VALIDATION DES CONFIGURATIONS KUBERNETES"
                            echo "============================================="
                            
                            # Tests basés sur les manifests générés
                            SCORE=0
                            
                            if [ -f "k8s-deploy/deployment.yaml" ]; then
                                echo "✅ Manifest de déploiement trouvé"
                                
                                # Test Security Context
                                if grep -q "runAsUser: 1000" k8s-deploy/deployment.yaml; then
                                    echo "✅ Utilisateur non-root configuré"
                                    SCORE=$((SCORE + 25))
                                fi
                                
                                if grep -q "readOnlyRootFilesystem: true" k8s-deploy/deployment.yaml; then
                                    echo "✅ Filesystem read-only configuré"
                                    SCORE=$((SCORE + 25))
                                fi
                                
                                if grep -q "serviceAccountName:" k8s-deploy/deployment.yaml; then
                                    echo "✅ ServiceAccount personnalisé"
                                    SCORE=$((SCORE + 25))
                                fi
                                
                                if grep -q "capabilities:" k8s-deploy/deployment.yaml; then
                                    echo "✅ Capabilities configurées"
                                    SCORE=$((SCORE + 25))
                                fi
                            fi
                            
                            echo "📊 Score de sécurité Kubernetes: ${SCORE}/100"
                            echo "Score: ${SCORE}/100" > k8s-security-score.txt
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Erreur tests K8s: ${e.message}"
                        sh 'echo "Erreur tests" > k8s-security-score.txt'
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
                        sh '''
                        if command -v cosign >/dev/null 2>&1; then
                            echo "🔑 Cosign disponible"
                            # cosign sign nécessite des credentials
                            echo "⚠️ Signature simulée (credentials requis)"
                        else
                            echo "⚠️ Cosign non installé"
                        fi
                        '''
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
                        def zapOutput = sh(script: """
                            mkdir -p zap-output
                            docker run --network=host -v \$(pwd):/zap/wrk/:rw ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -r zap-report.html -I > zap-output.log 2>&1 || true
                            if [ ! -f "zap-report.html" ]; then
                                cat zap-output.log | grep -A 3 "WARN-NEW\\|FAIL-NEW" > zap-alerts.txt
                                echo "<html><body><h1>ZAP Scan Results</h1><pre>" > zap-report.html
                                cat zap-alerts.txt >> zap-report.html
                                echo "</pre></body></html>" >> zap-report.html
                            fi
                            cat zap-output.log
                        """, returnStdout: true)
                        
                        echo "Résultat du scan ZAP:"
                        echo zapOutput
                        
                        sh 'cp zap-report.html zap-report1.html || touch zap-report1.html'
                    } catch (Exception e) {
                        echo "Erreur lors du scan ZAP: ${e.message}"
                        sh '''
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
                        if [ ! -f "zap-alerts.txt" ]; then
                            if [ -f "zap-report.html" ] || [ -f "zap-report1.html" ]; then
                                REPORT_FILE=""
                                if [ -f "zap-report.html" ]; then
                                    REPORT_FILE="zap-report.html"
                                else
                                    REPORT_FILE="zap-report1.html"
                                fi
                                
                                grep -A 5 "WARN-NEW\\|FAIL-NEW" $REPORT_FILE > zap-alerts.txt 2>/dev/null || echo "Extraction des alertes échouée"
                                
                                if [ ! -s "zap-alerts.txt" ]; then
                                    echo "Impossible d'extraire les alertes du rapport ZAP" > zap-alerts.txt
                                fi
                            else
                                echo "Aucun rapport ZAP n'a été généré" > zap-alerts.txt
                            fi
                        fi
                        
                        echo "Contenu de zap-alerts.txt:"
                        cat zap-alerts.txt
                        
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
                        mkdir -p security-reports
                        
                        # Copie des rapports
                        for report in trivy-sca-report.txt trivy-image-report.txt trivy-k8s-report.txt k8s-security-score.txt zap-report.html zap-report1.html zap-alerts.txt; do
                            if [ -f "$report" ]; then
                                cp "$report" security-reports/
                            fi
                        done
                        
                        # Copie des manifests K8s
                        if [ -d "k8s-deploy" ]; then
                            cp -r k8s-deploy security-reports/
                        fi
                        
                        # Rapport combiné AVEC section Kubernetes
                        echo "# 🛡️ Rapport de sécurité combiné pour Demo App + Kubernetes" > combined-security-report.txt
                        echo "## Date: $(date)" >> combined-security-report.txt
                        echo "## Build: ${BUILD_NUMBER}" >> combined-security-report.txt
                        echo "" >> combined-security-report.txt
                        
                        # 🆕 Section Kubernetes
                        if [ -f "k8s-security-score.txt" ] || [ -d "k8s-deploy" ]; then
                            echo "## 🏛️ SÉCURITÉ KUBERNETES - 3 PILIERS" >> combined-security-report.txt
                            echo "" >> combined-security-report.txt
                            
                            if [ -f "k8s-security-score.txt" ]; then
                                echo "### 📊 Score de sécurité:" >> combined-security-report.txt
                                cat k8s-security-score.txt >> combined-security-report.txt
                                echo "" >> combined-security-report.txt
                            fi
                            
                            echo "### 🛡️ Pilier 1: Pods Sécurisés" >> combined-security-report.txt
                            if [ -f "k8s-deploy/deployment.yaml" ]; then
                                if grep -q "runAsUser: 1000" k8s-deploy/deployment.yaml; then echo "✅ Utilisateur non-root configuré"; else echo "❌ Utilisateur root détecté"; fi >> combined-security-report.txt
                                if grep -q "readOnlyRootFilesystem: true" k8s-deploy/deployment.yaml; then echo "✅ Filesystem read-only activé"; else echo "❌ Filesystem en écriture"; fi >> combined-security-report.txt
                            fi
                            echo "" >> combined-security-report.txt
                            
                            echo "### 🔐 Pilier 2: RBAC" >> combined-security-report.txt
                            if [ -f "k8s-deploy/rbac.yaml" ]; then echo "✅ Configuration RBAC présente"; else echo "❌ RBAC non configuré"; fi >> combined-security-report.txt
                            echo "" >> combined-security-report.txt
                            
                            echo "### 🔒 Pilier 3: Isolation" >> combined-security-report.txt
                            if [ -f "k8s-deploy/networkpolicy.yaml" ]; then echo "✅ NetworkPolicies configurées"; else echo "❌ Isolation réseau manquante"; fi >> combined-security-report.txt
                            echo "" >> combined-security-report.txt
                        fi
                        
                        # Sections existantes
                        echo "## Rapport d'analyse des dépendances (Trivy SCA)" >> combined-security-report.txt
                        if [ -f "trivy-sca-report.txt" ]; then
                            cat trivy-sca-report.txt >> combined-security-report.txt
                        else
                            echo "Rapport SCA non disponible" >> combined-security-report.txt
                        fi
                        
                        echo "\n## Rapport de scan d'image (Trivy)" >> combined-security-report.txt
                        if [ -f "trivy-image-report.txt" ]; then
                            cat trivy-image-report.txt >> combined-security-report.txt
                        else
                            echo "Rapport de scan d'image non disponible" >> combined-security-report.txt
                        fi
                        
                        echo "\n## Résultats principaux du scan DAST (ZAP)" >> combined-security-report.txt
                        if [ -f "zap-alerts.txt" ]; then
                            cat zap-alerts.txt >> combined-security-report.txt
                        else
                            echo "Résultats ZAP non disponibles" >> combined-security-report.txt
                        fi
                        
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
                        
                        def reportContent = ""
                        try {
                            reportContent = readFile('combined-security-report.txt')
                        } catch (Exception e) {
                            reportContent = "Rapport non généré. Conseils généraux sur la sécurité des conteneurs et Kubernetes demandés."
                        }
                        
                        // 🆕 Prompt enrichi avec Kubernetes
                        def mistralPrompt = """En tant qu'expert en cybersécurité DevSecOps et Kubernetes, analyse ce rapport et fournit:

1. 🏛️ ANALYSE DES 3 PILIERS KUBERNETES:
   - Pods Sécurisés (Security Context)
   - RBAC (Role-Based Access Control)
   - Isolation (NetworkPolicies)

2. 🔍 PROBLÈMES CRITIQUES identifiés
3. 📋 RECOMMANDATIONS prioritaires  
4. 🛠️ SOLUTIONS techniques précises
5. 📊 SCORE de sécurité global

Rapport: ${reportContent}"""

                        writeFile file: 'mistral-prompt.txt', text: mistralPrompt
                        
                        writeFile file: 'create_mistral_request.py', text: '''
import json

with open('mistral-prompt.txt', 'r') as f:
    prompt = f.read()

request = {
    "model": "mistral-large-latest",
    "messages": [{"role": "user", "content": prompt}],
    "temperature": 0.2,
    "max_tokens": 4000
}

with open('mistral-request.json', 'w') as f:
    json.dump(request, f)
'''
                        
                        sh 'python3 create_mistral_request.py'
                        
                        def curlCommand = """
                        curl -s -X POST "${MISTRAL_API_URL}" \\
                        -H "Content-Type: application/json" \\
                        -H "Authorization: Bearer ${MISTRAL_API_KEY}" \\
                        -d @mistral-request.json > mistral-response.json || echo '{"error":"Erreur API"}' > mistral-response.json
                        """
                        
                        sh curlCommand
                        
                        writeFile file: 'extract_response.py', text: '''
import json

try:
    with open('mistral-response.json', 'r') as f:
        response = json.load(f)
    
    if 'choices' in response and len(response['choices']) > 0:
        print(response['choices'][0]['message']['content'])
    else:
        print("Erreur lors de l'appel API Mistral")
except Exception as e:
    print(f"Erreur: {str(e)}")
'''
                        
                        def recommendations = sh(script: 'python3 extract_response.py', returnStdout: true).trim()
                        writeFile file: 'security-recommendations.md', text: recommendations
                        
                        echo "Recommandations de sécurité générées: security-recommendations.md"
                    } catch (Exception e) {
                        echo "Erreur lors de la consultation Mistral AI: ${e.message}"
                        writeFile file: 'security-recommendations.md', text: """# Recommandations de sécurité

## 🏛️ Validation des 3 Piliers Kubernetes
1. **Pods Sécurisés**: Vérifier Security Context avec runAsUser: 1000
2. **RBAC**: Configurer ServiceAccount avec permissions minimales  
3. **Isolation**: Déployer NetworkPolicies restrictives

## 🔧 Actions prioritaires
- Corriger les vulnérabilités HIGH/CRITICAL trouvées par Trivy
- Valider la configuration Kubernetes avant déploiement
- Implémenter les tests de sécurité automatisés

Erreur API: ${e.message}
"""
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }
    
    post {
        success {
            echo '✅ Pipeline de sécurité CI/CD + Kubernetes réussi!'
            if (fileExists('k8s-deploy/deployment.yaml')) {
                echo '🎉 Manifests Kubernetes sécurisés générés!'
            }
            echo 'Les recommandations sont disponibles dans security-recommendations.md'
        }
        unstable {
            echo '⚠ Pipeline terminé avec avertissements. Vérifiez les rapports.'
        }
        failure {
            echo '❌ Échec critique du pipeline.'
        }
        always {
            archiveArtifacts artifacts: '*.txt, *.html, *.json, *.md, k8s-deploy/*, security-reports/*, zap-output.log', allowEmptyArchive: true
            
            // Résumé final
            sh '''
                echo ""
                echo "🏆 RÉSUMÉ DU PIPELINE:"
                echo "📅 $(date)"
                echo "🏗️ Build: ${BUILD_NUMBER}"
                if [ -f "k8s-security-score.txt" ]; then
                    echo "🛡️ $(cat k8s-security-score.txt)"
                fi
                echo "📦 Artefacts archivés avec succès"
            '''
        }
    }
}
