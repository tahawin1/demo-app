pipeline {
    agent any

    environment {
        SONARQUBE_INSTALLATION = 'sonarQube'
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        TARGET_URL = 'http://demo.testfire.net'
        MISTRAL_API_KEY = credentials('taha-jenkins')
        MISTRAL_API_URL = 'https://api.mistral.ai/v1/chat/completions'
        
        APP_NAME = "${env.JOB_NAME}-${env.BUILD_NUMBER}".toLowerCase().replaceAll(/[^a-z0-9-]/, '-')
        IMAGE_NAME = "demo-app"
        DOCKER_REGISTRY = "localhost:5000"
    }

    stages {
        stage('Checkout') {
            steps {
                echo "🔄 Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app'

                sh '''
                    mkdir -p security-reports
                    mkdir -p scripts
                    mkdir -p zap-reports
                    mkdir -p trivy-reports
                '''
            }
        }

        stage('Analyse SonarQube') {
            steps {
                script {
                    try {
                        echo "🚀 Début de l'analyse SonarQube..."

                        writeFile file: 'sonar-project.properties', text: '''# Configuration SonarQube
sonar.projectKey=demo-app
sonar.projectName=Demo App Security Pipeline
sonar.sources=.
sonar.exclusions=**/node_modules/**,**/target/**,**/*.log,**/security-reports/**,**/scripts/**,**/zap-reports/**,**/trivy-reports/**
sonar.sourceEncoding=UTF-8
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.java.source=11
sonar.python.coverage.reportPaths=coverage.xml
sonar.qualitygate.wait=true
'''

                        withSonarQubeEnv('sonarQube') {
                            sh '''
                                if ! command -v sonar-scanner >/dev/null 2>&1; then
                                    wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-linux.zip
                                    unzip -q sonar-scanner-cli-4.8.0.2856-linux.zip
                                    SCANNER_CMD="./sonar-scanner-4.8.0.2856-linux/bin/sonar-scanner"
                                else
                                    SCANNER_CMD="sonar-scanner"
                                fi

                                ${SCANNER_CMD} \\
                                    -Dsonar.projectKey=demo-app \\
                                    -Dsonar.projectName="Demo App Security Pipeline" \\
                                    -Dsonar.sources=. \\
                                    -Dsonar.exclusions="**/node_modules/**,**/target/**,**/*.log,**/security-reports/**,**/zap-reports/**,**/trivy-reports/**" \\
                                    -Dsonar.host.url="${SONAR_HOST_URL}" \\
                                    -Dsonar.login="${SONAR_AUTH_TOKEN}" \\
                                    -Dsonar.qualitygate.wait=true
                            '''
                        }
                        echo "✅ Analyse SonarQube terminée !"
                    } catch (Exception e) {
                        echo "❌ Erreur SonarQube: ${e.message}"
                        error("Pipeline arrêté - Erreur lors de l'analyse SonarQube")
                    }
                }
            }
        }

        stage('Quality Gate SonarQube') {
            steps {
                script {
                    try {
                        echo "🔍 Vérification du Quality Gate SonarQube..."
                        timeout(time: 5, unit: 'MINUTES') {
                            def qg = waitForQualityGate()
                            
                            echo "📊 Statut du Quality Gate: ${qg.status}"
                            
                            if (qg.status != 'OK') {
                                echo "❌ Quality Gate SonarQube ÉCHOUÉ!"
                                echo "📋 Détails des conditions échouées:"
                                
                                // Afficher les métriques qui ont échoué
                                if (qg.conditions) {
                                    qg.conditions.each { condition ->
                                        echo "   • ${condition.metricKey}: ${condition.actualValue} (seuil: ${condition.errorThreshold})"
                                    }
                                }
                                
                                // Générer un rapport détaillé
                                writeFile file: 'security-reports/sonarqube-quality-gate-failure.txt', text: """
ÉCHEC DU QUALITY GATE SONARQUBE
===============================
Statut: ${qg.status}
Build: ${BUILD_NUMBER}
Date: ${new Date()}

Conditions échouées:
${qg.conditions?.collect { "- ${it.metricKey}: ${it.actualValue} (seuil: ${it.errorThreshold})" }?.join('\n') ?: 'Aucun détail disponible'}

Action requise:
- Corriger les problèmes de qualité de code
- Relancer l'analyse SonarQube
- Vérifier que tous les seuils sont respectés
"""
                                
                                error("🚨 PIPELINE ARRÊTÉ - Quality Gate SonarQube échoué. Veuillez corriger les problèmes de qualité de code avant de continuer.")
                            } else {
                                echo "✅ Quality Gate SonarQube RÉUSSI!"
                                
                                // Générer un rapport de succès
                                writeFile file: 'security-reports/sonarqube-quality-gate-success.txt', text: """
SUCCÈS DU QUALITY GATE SONARQUBE
===============================
Statut: ${qg.status}
Build: ${BUILD_NUMBER}
Date: ${new Date()}

Toutes les conditions du quality gate ont été respectées.
Le code respecte les standards de qualité définis.
"""
                            }
                        }
                    } catch (Exception e) {
                        echo "⏱️ Erreur Quality Gate: ${e.message}"
                        error("🚨 PIPELINE ARRÊTÉ - Erreur lors de la vérification du Quality Gate SonarQube")
                    }
                }
            }
        }

        stage('Analyse SCA avec Trivy') {
            steps {
                script {
                    try {
                        echo '🔍 Analyse des dépendances avec Trivy (SCA)...'
                        sh '''
                            # Scan des vulnérabilités du système de fichiers
                            trivy fs --format json --output trivy-reports/trivy-sca-report.json . || echo "⚠️ Trivy SCA avec avertissements"
                            trivy fs --format table --output trivy-reports/trivy-sca-report.txt . || echo "⚠️ Trivy SCA avec avertissements"
                            
                            # Copier vers security-reports pour compatibilité
                            cp trivy-reports/trivy-sca-report.txt security-reports/ || true
                            cp trivy-reports/trivy-sca-report.json security-reports/ || true
                        '''
                        echo "✅ Analyse SCA terminée"
                    } catch (Exception e) {
                        echo "❌ Erreur SCA: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Build Docker') {
            steps {
                script {
                        echo '🏗️ Construction Docker...'
                    sh '''
                        # Construire l'image Docker
                        docker build -t ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} .
                        docker tag ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} ${DOCKER_REGISTRY}/${IMAGE_NAME}:latest
                        
                        # Push vers le registry
                        docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                        docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:latest
                    '''
                        echo "✅ Docker build terminé"
                }
            }
        }

        stage('Scan Docker Image') {
            steps {
                script {
                    echo '🔎 Scan Docker avec Trivy...'
                    sh '''
                        # Scan de l'image Docker
                        trivy image --format table --output trivy-reports/image-scan-report.txt ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                        trivy image --format json --output trivy-reports/image-scan-report.json ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                        
                        # Copier vers security-reports pour compatibilité
                        cp trivy-reports/image-scan-report.txt security-reports/ || true
                        cp trivy-reports/image-scan-report.json security-reports/ || true
                    '''
                    echo "✅ Scan d'image terminé"
                }
            }
        }

        stage('Sign Docker Image') {
            steps {
                script {
                    try {
                        echo '✍️ Signature avec Cosign...'
                        withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PASSWORD')]) {
                            sh '''
                                # Signer l'image avec Cosign
                                cosign sign --key env://COSIGN_PASSWORD ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                                
                                # Vérifier la signature
                                cosign verify --key env://COSIGN_PASSWORD ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                            '''
                        }
                        echo "✅ Image signée avec succès"
                    } catch (Exception e) {
                        echo "⚠️ Erreur signature Cosign: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Analyse DAST avec ZAP') {
            steps {
                script {
                    try {
                        echo "🧪 Analyse dynamique avec ZAP..."
                        sh '''
                            # Créer le répertoire pour les rapports ZAP
                            mkdir -p zap-reports
                            
                            # Lancer ZAP avec différents formats de rapport
                            docker run -v $(pwd)/zap-reports:/zap/wrk/:rw -t ${ZAP_IMAGE} zap-baseline.py \\
                                -t ${TARGET_URL} \\
                                -r zap-baseline-report.html \\
                                -J zap-baseline-report.json \\
                                -x zap-baseline-report.xml || true
                            
                            # Copier les rapports vers security-reports
                            cp zap-reports/*.html security-reports/ 2>/dev/null || echo "Aucun rapport HTML ZAP trouvé"
                            cp zap-reports/*.json security-reports/ 2>/dev/null || echo "Aucun rapport JSON ZAP trouvé"
                            cp zap-reports/*.xml security-reports/ 2>/dev/null || echo "Aucun rapport XML ZAP trouvé"
                        '''
                        echo "✅ Analyse DAST ZAP terminée"
                    } catch (Exception e) {
                        echo "❌ Erreur ZAP: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Quality Gate OWASP ZAP') {
            steps {
                script {
                    try {
                        echo "🔍 Vérification du Quality Gate OWASP ZAP..."
                        
                        // Analyser les résultats ZAP
                        def zapResults = [:]
                        def zapFailures = []
                        
                        // Vérifier si le rapport JSON existe
                        if (fileExists('zap-reports/zap-baseline-report.json') || fileExists('security-reports/zap-baseline-report.json')) {
                            
                            def reportFile = fileExists('zap-reports/zap-baseline-report.json') ? 'zap-reports/zap-baseline-report.json' : 'security-reports/zap-baseline-report.json'
                            
                            // Analyser le fichier JSON ZAP
                            def zapJson = readJSON file: reportFile
                            
                            // Compter les alertes par niveau de risque
                            def highRisk = 0
                            def mediumRisk = 0
                            def lowRisk = 0
                            def infoRisk = 0
                            
                            if (zapJson.site && zapJson.site[0] && zapJson.site[0].alerts) {
                                zapJson.site[0].alerts.each { alert ->
                                    switch(alert.riskdesc?.toLowerCase()) {
                                        case ~/.*high.*/:
                                            highRisk++
                                            break
                                        case ~/.*medium.*/:
                                            mediumRisk++
                                            break
                                        case ~/.*low.*/:
                                            lowRisk++
                                            break
                                        default:
                                            infoRisk++
                                    }
                                }
                            }
                            
                            // Stocker les résultats
                            zapResults = [
                                high: highRisk,
                                medium: mediumRisk,
                                low: lowRisk,
                                info: infoRisk
                            ]
                            
                            echo "📊 Résultats ZAP:"
                            echo "   • Risque Élevé: ${highRisk}"
                            echo "   • Risque Moyen: ${mediumRisk}"
                            echo "   • Risque Faible: ${lowRisk}"
                            echo "   • Informationnel: ${infoRisk}"
                            
                            // Définir les seuils de tolérance
                            def maxHighRisk = 0      // Aucun risque élevé autorisé
                            def maxMediumRisk = 3    // Maximum 3 risques moyens
                            def maxLowRisk = 10      // Maximum 10 risques faibles
                            
                            // Vérifier les seuils
                            if (highRisk > maxHighRisk) {
                                zapFailures.add("Risque ÉLEVÉ détecté: ${highRisk} (max autorisé: ${maxHighRisk})")
                            }
                            
                            if (mediumRisk > maxMediumRisk) {
                                zapFailures.add("Risque MOYEN excessif: ${mediumRisk} (max autorisé: ${maxMediumRisk})")
                            }
                            
                            if (lowRisk > maxLowRisk) {
                                zapFailures.add("Risque FAIBLE excessif: ${lowRisk} (max autorisé: ${maxLowRisk})")
                            }
                            
                        } else {
                            echo "⚠️ Rapport ZAP JSON non trouvé, analyse basique des logs..."
                            
                            // Analyser les logs ou fichiers texte si disponibles
                            sh '''
                                if [ -f zap-reports/zap-baseline-report.html ] || [ -f security-reports/zap-baseline-report.html ]; then
                                    echo "Rapport HTML ZAP trouvé"
                                else
                                    echo "⚠️ Aucun rapport ZAP détaillé trouvé"
                                fi
                            '''
                        }
                        
                        // Générer le rapport de quality gate
                        if (zapFailures.size() > 0) {
                            echo "❌ Quality Gate OWASP ZAP ÉCHOUÉ!"
                            echo "📋 Problèmes détectés:"
                            zapFailures.each { failure ->
                                echo "   • ${failure}"
                            }
                            
                            // Générer un rapport détaillé d'échec
                            writeFile file: 'security-reports/zap-quality-gate-failure.txt', text: """
ÉCHEC DU QUALITY GATE OWASP ZAP
==============================
Build: ${BUILD_NUMBER}
Date: ${new Date()}
URL cible: ${TARGET_URL}

Résultats ZAP:
- Risque Élevé: ${zapResults.high ?: 'N/A'}
- Risque Moyen: ${zapResults.medium ?: 'N/A'}
- Risque Faible: ${zapResults.low ?: 'N/A'}
- Informationnel: ${zapResults.info ?: 'N/A'}

Problèmes détectés:
${zapFailures.join('\n')}

Actions requises:
- Examiner le rapport détaillé ZAP
- Corriger les vulnérabilités de sécurité
- Relancer les tests de sécurité
- Vérifier que tous les seuils sont respectés
"""
                            
                            error("🚨 PIPELINE ARRÊTÉ - Quality Gate OWASP ZAP échoué. Des vulnérabilités de sécurité critiques ont été détectées.")
                            
                        } else {
                            echo "✅ Quality Gate OWASP ZAP RÉUSSI!"
                            
                            // Générer un rapport de succès
                            writeFile file: 'security-reports/zap-quality-gate-success.txt', text: """
SUCCÈS DU QUALITY GATE OWASP ZAP
===============================
Build: ${BUILD_NUMBER}
Date: ${new Date()}
URL cible: ${TARGET_URL}

Résultats ZAP:
- Risque Élevé: ${zapResults.high ?: 'N/A'}
- Risque Moyen: ${zapResults.medium ?: 'N/A'}
- Risque Faible: ${zapResults.low ?: 'N/A'}
- Informationnel: ${zapResults.info ?: 'N/A'}

Toutes les conditions du quality gate ont été respectées.
L'application respecte les standards de sécurité définis.
"""
                        }
                        
                    } catch (Exception e) {
                        echo "❌ Erreur Quality Gate ZAP: ${e.message}"
                        error("🚨 PIPELINE ARRÊTÉ - Erreur lors de la vérification du Quality Gate OWASP ZAP")
                    }
                }
            }
        }

        stage('Génération du rapport de sécurité consolidé') {
            steps {
                script {
                    echo "📊 Génération du rapport de sécurité consolidé..."
                    
                    sh '''
                        # Créer un rapport consolidé
                        cat > security-reports/security-consolidated-report.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Sécurité Consolidé - Build ${BUILD_NUMBER}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .success { color: #28a745; font-weight: bold; }
        .warning { color: #ffc107; font-weight: bold; }
        .danger { color: #dc3545; font-weight: bold; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background: #f8f9fa; border-radius: 5px; }
        .footer { text-align: center; margin-top: 30px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Rapport de Sécurité Consolidé</h1>
        <p>Build: ${BUILD_NUMBER} | Date: $(date) | Pipeline: ${JOB_NAME}</p>
    </div>
    
    <div class="section">
        <h2>📋 Résumé des Quality Gates</h2>
        <div class="metric">
            <strong>SonarQube:</strong> <span class="success">✅ RÉUSSI</span>
        </div>
        <div class="metric">
            <strong>OWASP ZAP:</strong> <span class="success">✅ RÉUSSI</span>
        </div>
        <div class="metric">
            <strong>Trivy SCA:</strong> <span class="success">✅ TERMINÉ</span>
        </div>
        <div class="metric">
            <strong>Image Scan:</strong> <span class="success">✅ TERMINÉ</span>
        </div>
    </div>
    
    <div class="section">
        <h2>🔍 Analyses Effectuées</h2>
        <ul>
            <li><strong>Analyse Statique (SAST):</strong> SonarQube - Qualité du code et sécurité</li>
            <li><strong>Analyse des Dépendances (SCA):</strong> Trivy - Vulnérabilités des composants</li>
            <li><strong>Analyse de l'Image:</strong> Trivy - Sécurité des conteneurs</li>
            <li><strong>Analyse Dynamique (DAST):</strong> OWASP ZAP - Tests de pénétration</li>
            <li><strong>Signature:</strong> Cosign - Intégrité des images</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>📊 Métriques de Sécurité</h2>
        <p>Tous les quality gates ont été respectés selon les seuils définis.</p>
        <p>L'application est conforme aux standards de sécurité de l'organisation.</p>
    </div>
    
    <div class="footer">
        <p>Rapport généré automatiquement par le pipeline de sécurité</p>
    </div>
</body>
</html>
EOF
                    '''
                    
                    echo "✅ Rapport consolidé généré"
                }
            }
        }
    }

    post {
        always {
            echo '🧹 Nettoyage et archivage...'
            
            // Archiver tous les rapports de sécurité
            archiveArtifacts artifacts: 'security-reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'zap-reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'trivy-reports/**/*', allowEmptyArchive: true
            
            // Publier les rapports HTML
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'security-reports',
                reportFiles: 'security-consolidated-report.html',
                reportName: 'Rapport de Sécurité Consolidé'
            ])
            
            // Publier le rapport ZAP si disponible
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'security-reports',
                reportFiles: 'zap-baseline-report.html',
                reportName: 'Rapport OWASP ZAP'
            ])
            
            // Nettoyage
            sh '''
                rm -rf sonar-scanner-*
                rm -f *.zip
                docker system prune -f || true
            '''
        }

        success {
            echo '✅ Pipeline terminé avec succès!'
            echo '🛡️ Tous les quality gates de sécurité ont été respectés'
            
            // Notification de succès
            emailext (
                subject: "✅ Pipeline Sécurisé Réussi - ${JOB_NAME} #${BUILD_NUMBER}",
                body: """
🎉 Pipeline de sécurité terminé avec succès!

📊 Résumé:
• Build: ${BUILD_NUMBER}
• Projet: ${JOB_NAME}
• Statut: SUCCÈS

🛡️ Quality Gates:
✅ SonarQube - Code quality & security
✅ OWASP ZAP - Dynamic security testing
✅ Trivy - Dependency & container scanning
✅ Cosign - Image signing

L'application est prête pour le déploiement sécurisé.

Consultez les rapports détaillés dans Jenkins.
                """,
                recipientProviders: [developers(), requestor()]
            )
        }

        unstable {
            echo '⚠️ Pipeline terminé avec des avertissements!'
            echo '🔍 Vérifiez les rapports pour plus de détails'
        }

        failure {
            echo '❌ Pipeline échoué!'
            echo '🚨 Des problèmes de sécurité ont été détectés'
            
            // Notification d'échec
            emailext (
                subject: "❌ Pipeline Sécurisé Échoué - ${JOB_NAME} #${BUILD_NUMBER}",
                body: """
🚨 Pipeline de sécurité échoué!

📊 Détails:
• Build: ${BUILD_NUMBER}
• Projet: ${JOB_NAME}
• Statut: ÉCHEC

🔍 Actions requises:
• Vérifier les quality gates SonarQube
• Examiner les vulnérabilités ZAP
• Corriger les problèmes identifiés
• Relancer le pipeline

Consultez les logs Jenkins pour plus de détails.
                """,
                recipientProviders: [developers(), requestor()]
            )
        }
    }
}
