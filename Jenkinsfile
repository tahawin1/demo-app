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
        
        // SEUILS CRITIQUES POUR QUALITY GATES - AJUSTABLES
        MAX_CRITICAL_VULNS = '1'      // Autoriser 1 vulnérabilité critique
        MAX_HIGH_VULNS = '6'          // Autoriser jusqu'à 6 vulnérabilités HIGH
        MAX_MEDIUM_VULNS = '5'        // Maximum 5 vulnérabilités MEDIUM
        
        // SIMULATION D'ÉCHEC - Forcer l'échec du Quality Gate SonarQube
        FORCE_SONAR_FAILURE = 'true'
    }

    stages {
        stage('Checkout') {
            steps {
                echo "🔄 Clonage du depot..."
                git 'https://github.com/tahawin1/demo-app'
                sh 'mkdir -p security-reports scripts zap-reports trivy-reports'
                
                // Créer des fichiers de test avec des problèmes pour SonarQube
                writeFile file: 'TestFile.java', text: '''
public class TestFile {
    // Code avec problèmes de qualité pour déclencher échec SonarQube
    public void badMethod() {
        String password = "hardcoded_password"; // Vulnérabilité de sécurité
        System.out.println(password);
        
        // Code dupliqué
        int x = 1;
        int y = 2;
        int z = x + y;
        
        // Complexité cyclomatique élevée
        if (x > 0) {
            if (y > 0) {
                if (z > 0) {
                    if (x > y) {
                        if (y > z) {
                            System.out.println("Complex logic");
                        }
                    }
                }
            }
        }
    }
    
    // Méthode non utilisée
    private void unusedMethod() {
        // Code mort
    }
}
'''
                echo "✅ Checkout terminé - Fichiers de test créés"
            }
        }

        stage('Analyse SonarQube') {
            steps {
                script {
                    try {
                        echo "🔍 Debut de l'analyse SonarQube..."
                        
                        // Configuration SonarQube avec règles strictes
                        writeFile file: 'sonar-project.properties', text: '''sonar.projectKey=demo-app-test
sonar.projectName=Demo App Security Pipeline Test
sonar.sources=.
sonar.exclusions=**/node_modules/**,**/target/**,**/*.log,**/security-reports/**
sonar.sourceEncoding=UTF-8
sonar.qualitygate.wait=true
sonar.java.source=11
sonar.java.target=11
sonar.java.binaries=.
# Règles strictes pour forcer l'échec
sonar.java.coveragePlugin=jacoco
sonar.coverage.exclusions=**/*
'''

                        def javaVersion = sh(script: 'java -version 2>&1 | head -1', returnStdout: true).trim()
                        echo "Version Java détectée: ${javaVersion}"
                        
                        def sonarUrl = env.SONAR_HOST_URL ?: "http://localhost:9000"
                        def sonarStatus = sh(script: "curl -s -o /dev/null -w '%{http_code}' ${sonarUrl} || echo '000'", returnStdout: true).trim()
                        
                        if (sonarStatus != "200") {
                            echo "⚠️ SonarQube non accessible (status: ${sonarStatus})"
                            echo "🔧 Simulation d'un serveur SonarQube configuré avec Quality Gate strict"
                            
                            // Simuler une analyse SonarQube qui va échouer
                            writeFile file: 'security-reports/sonarqube-analysis-simulation.txt', text: '''
SIMULATION ANALYSE SONARQUBE
=============================
Projet: demo-app-test
Analyse terminée avec ÉCHEC

PROBLÈMES DÉTECTÉS:
🔴 Bugs: 15 (seuil: 0)
🔴 Vulnérabilités: 8 (seuil: 0) 
🔴 Code Smells: 127 (seuil: 50)
🔴 Couverture: 0% (seuil: 80%)
🔴 Duplication: 25% (seuil: 3%)
🔴 Complexité cyclomatique: 45 (seuil: 10)

VULNÉRABILITÉS CRITIQUES:
- Mot de passe codé en dur (TestFile.java:4)
- Injection SQL potentielle (TestFile.java:12)
- Utilisation d'algorithmes cryptographiques faibles

QUALITY GATE: ÉCHEC
Conditions échouées: 6/8
'''
                            
                            writeFile file: 'security-reports/sonarqube-simulated-success.txt', text: "SonarQube analyse simulée terminée - ÉCHEC ATTENDU"
                            echo "✅ Analyse SonarQube simulée terminée (avec problèmes critiques)"
                            return
                        }

                        withSonarQubeEnv('sonarQube') {
                            sh '''
                                export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
                                export PATH=$JAVA_HOME/bin:$PATH
                                
                                if ! command -v sonar-scanner >/dev/null 2>&1; then
                                    echo "📥 Téléchargement SonarQube Scanner..."
                                    wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip
                                    unzip -q sonar-scanner-cli-5.0.1.3006-linux.zip
                                    SCANNER_CMD="./sonar-scanner-5.0.1.3006-linux/bin/sonar-scanner"
                                else
                                    SCANNER_CMD="sonar-scanner"
                                fi

                                echo "🔍 Exécution SonarQube Scanner..."
                                ${SCANNER_CMD} \
                                    -Dsonar.projectKey=demo-app-test \
                                    -Dsonar.sources=. \
                                    -Dsonar.exclusions="**/node_modules/**,**/target/**,**/security-reports/**" \
                                    -Dsonar.host.url="${SONAR_HOST_URL}" \
                                    -Dsonar.token="${SONAR_AUTH_TOKEN}" \
                                    -Dsonar.java.binaries=. \
                                    -Dsonar.qualitygate.wait=true
                            '''
                        }
                        
                        writeFile file: 'security-reports/sonarqube-success.txt', text: "SonarQube analyse terminée avec succès"
                        echo "✅ Analyse SonarQube réelle terminée"
                        
                    } catch (Exception e) {
                        echo "❌ Erreur SonarQube: ${e.message}"
                        writeFile file: 'security-reports/sonarqube-error.txt', text: "SonarQube échoué: ${e.message}"
                        
                        // Créer une simulation d'analyse avec échec
                        writeFile file: 'security-reports/sonarqube-analysis-simulation.txt', text: """
ANALYSE SONARQUBE ÉCHOUÉE
========================
Erreur: ${e.message}

SIMULATION - Problèmes critiques détectés:
🔴 Quality Gate: FAILED
🔴 Bugs critiques: 12
🔴 Vulnérabilités de sécurité: 8
🔴 Couverture insuffisante: 15%
                        """
                        
                        writeFile file: 'security-reports/sonarqube-simulated-success.txt', text: "SonarQube analyse simulée (erreur de config mais problèmes détectés)"
                    }
                }
            }
        }

        stage('💥 Quality Gate SonarQube') {
            steps {
                script {
                    try {
                        echo "🔍 Vérification Quality Gate SonarQube..."
                        
                        if (!fileExists('security-reports/sonarqube-simulated-success.txt') && !fileExists('security-reports/sonarqube-success.txt')) {
                            echo "⚠️ SonarQube non exécuté - SKIP Quality Gate"
                            return
                        }
                        
                        // SIMULATION FORCÉE D'ÉCHEC DU QUALITY GATE
                        if (env.FORCE_SONAR_FAILURE == 'true') {
                            echo "🚨 SIMULATION: Quality Gate SonarQube configuré pour ÉCHOUER"
                            echo "📊 Problèmes simulés détectés:"
                            echo "   🔴 Bugs: 15 (seuil max: 0)"
                            echo "   🔴 Vulnérabilités: 8 (seuil max: 0)"
                            echo "   🔴 Code Smells: 127 (seuil max: 50)"
                            echo "   🔴 Couverture: 0% (seuil min: 80%)"
                            echo "   🔴 Duplication: 25% (seuil max: 3%)"
                            
                            def failureDetails = """
🚨 QUALITY GATE SONARQUBE ÉCHOUÉ - DÉTAILS

❌ CONDITIONS ÉCHOUÉES:
1. 🐛 Bugs: 15 trouvés (Maximum autorisé: 0)
   - Null pointer dereference: 5 occurrences
   - Resource leak: 3 occurrences  
   - Logic error: 7 occurrences

2. 🔐 Vulnérabilités: 8 trouvées (Maximum autorisé: 0)
   - Hardcoded password: 2 occurrences
   - SQL Injection: 3 occurrences
   - Weak cryptography: 3 occurrences

3. 🦨 Code Smells: 127 trouvés (Maximum autorisé: 50)
   - Cognitive complexity: 45 occurrences
   - Duplicated code: 35 occurrences
   - Dead code: 47 occurrences

4. 📊 Couverture: 0% (Minimum requis: 80%)
   - Aucun test unitaire détecté
   - Code non couvert: 100%

5. 🔄 Duplication: 25% (Maximum autorisé: 3%)
   - Blocs dupliqués: 15
   - Lignes dupliquées: 1,247

6. 🏗️ Maintenabilité: ÉCHEC
   - Debt ratio: 45% (Maximum: 5%)
   - Technical debt: 2d 15h

IMPACT SÉCURITÉ: CRITIQUE
RECOMMANDATION: ARRÊT IMMÉDIAT DU PIPELINE
            """
                            
                            writeFile file: 'security-reports/sonarqube-failure-details.txt', text: failureDetails
                            writeFile file: 'security-reports/sonarqube-failure.txt', text: "Quality Gate SonarQube ÉCHOUÉ - Statut: FAILED"
                            
                            echo "🛑 PIPELINE ARRÊTÉ - Quality Gate SonarQube échoué: FAILED"
                            echo "📋 Détails sauvegardés dans security-reports/sonarqube-failure-details.txt"
                            
                            error("🛑 PIPELINE ARRÊTÉ - Quality Gate SonarQube échoué: FAILED")
                        }
                        
                        // Si FORCE_SONAR_FAILURE n'est pas activé, essayer le vrai Quality Gate
                        timeout(time: 5, unit: 'MINUTES') {
                            def qg = waitForQualityGate()
                            echo "📊 Statut Quality Gate SonarQube: ${qg.status}"
                            
                            if (qg.status != 'OK') {
                                echo "🚨 QUALITY GATE SONARQUBE ÉCHOUÉ - ARRÊT DU PIPELINE"
                                writeFile file: 'security-reports/sonarqube-failure.txt', text: "Quality Gate SonarQube ÉCHOUÉ - Statut: ${qg.status}"
                                error("🛑 PIPELINE ARRÊTÉ - Quality Gate SonarQube échoué: ${qg.status}")
                            } else {
                                echo "✅ Quality Gate SonarQube RÉUSSI"
                                writeFile file: 'security-reports/sonarqube-qg-success.txt', text: "Quality Gate réussi - Statut: ${qg.status}"
                            }
                        }
                        
                    } catch (Exception e) {
                        if (e.message.contains("PIPELINE ARRÊTÉ")) {
                            // Créer un rapport d'échec détaillé avant de propager l'erreur
                            def finalReport = """
💥 ÉCHEC CRITIQUE DU PIPELINE - QUALITY GATE SONARQUBE
=====================================================
Date: ${new Date()}
Build: ${BUILD_NUMBER}
Étape: Quality Gate SonarQube

🚨 CAUSE DE L'ARRÊT:
${e.message}

🔍 ANALYSE:
Le pipeline s'est arrêté automatiquement lors de la vérification du Quality Gate SonarQube.
Des problèmes critiques de qualité et de sécurité ont été détectés dans le code.

❌ ÉTAPES NON EXÉCUTÉES:
- Analyse SCA avec Trivy (bloquée)
- Quality Gate SCA Trivy (bloquée)  
- Build Docker (bloquée)
- Trivy Scan (bloquée)
- Analyse DAST avec ZAP (bloquée)
- Quality Gate OWASP ZAP (bloquée)
- Consolidation des Rapports (bloquée)
- Consultation Mistral AI (bloquée)

🛡️ SÉCURITÉ:
Le pipeline a correctement empêché le déploiement d'un code non sécurisé.
La politique Zero Trust est respectée.

🔧 ACTIONS REQUISES:
1. Examiner les problèmes détectés par SonarQube
2. Corriger les vulnérabilités et bugs critiques
3. Améliorer la couverture de tests
4. Réduire la duplication de code
5. Relancer le pipeline après corrections

📊 DÉTAILS TECHNIQUES:
Consultez security-reports/sonarqube-failure-details.txt pour l'analyse complète.
            """
                            
                            writeFile file: 'security-reports/pipeline-stopped-sonarqube.txt', text: finalReport
                            
                            // Créer un rapport HTML simplifié pour l'échec
                            def failureHtmlReport = """<!DOCTYPE html>
<html>
<head>
    <title>💥 Pipeline ARRÊTÉ - Quality Gate SonarQube ÉCHOUÉ</title>
    <style>
        body { font-family: Arial; margin: 20px; background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%); }
        .header { background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .alert-critical { background: #f8d7da; border: 2px solid #dc3545; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .failure { color: #dc3545; font-weight: bold; }
        .blocked { color: #6c757d; text-decoration: line-through; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>💥 PIPELINE ARRÊTÉ</h1>
        <h2>Quality Gate SonarQube ÉCHOUÉ</h2>
        <p><strong>Build:</strong> ${BUILD_NUMBER} | <strong>Date:</strong> ${new Date()}</p>
    </div>
    
    <div class="alert-critical">
        <h2>🚨 ARRÊT AUTOMATIQUE DU PIPELINE</h2>
        <p class="failure">Le pipeline s'est arrêté automatiquement à l'étape "Quality Gate SonarQube" en raison de problèmes critiques détectés.</p>
        <p><strong>Politique de sécurité Zero Trust respectée:</strong> Aucun code non sécurisé ne peut progresser dans le pipeline.</p>
    </div>
    
    <div class="section">
        <h3>❌ Étapes NON Exécutées (Bloquées)</h3>
        <ul>
            <li class="blocked">📦 Analyse SCA avec Trivy</li>
            <li class="blocked">🔍 Quality Gate SCA Trivy</li>
            <li class="blocked">🐳 Build Docker</li>
            <li class="blocked">🔍 Trivy Scan</li>
            <li class="blocked">🕷️ Analyse DAST avec ZAP</li>
            <li class="blocked">🔍 Quality Gate OWASP ZAP</li>
            <li class="blocked">📋 Consolidation des Rapports</li>
            <li class="blocked">🤖 Consultation Mistral AI</li>
        </ul>
    </div>
    
    <div class="section">
        <h3>🔧 Actions Immédiates Requises</h3>
        <ol>
            <li><strong>Examiner les rapports SonarQube:</strong> Consulter security-reports/sonarqube-failure-details.txt</li>
            <li><strong>Corriger les vulnérabilités critiques</strong> identifiées</li>
            <li><strong>Réduire les bugs</strong> à 0 (actuellement: 15)</li>
            <li><strong>Améliorer la couverture de tests</strong> à minimum 80% (actuellement: 0%)</li>
            <li><strong>Réduire la duplication</strong> à maximum 3% (actuellement: 25%)</li>
            <li><strong>Relancer le pipeline</strong> après corrections</li>
        </ol>
    </div>
    
    <div class="section">
        <h3>📊 Résumé de l'Échec</h3>
        <pre>${finalReport}</pre>
    </div>
</body>
</html>"""
                            
                            writeFile file: 'security-reports/pipeline-failure-report.html', text: failureHtmlReport
                            
                            throw e // Propager l'erreur pour arrêter le pipeline
                        }
                        echo "⚠️ Erreur Quality Gate SonarQube: ${e.message} - CONTINUE"
                        writeFile file: 'security-reports/sonarqube-qg-error.txt', text: "Quality Gate SonarQube échoué: ${e.message}"
                    }
                }
            }
        }

        // TOUTES LES ÉTAPES SUIVANTES NE SERONT PAS EXÉCUTÉES SI SONARQUBE ÉCHOUE
        
        stage('📦 Analyse SCA avec Trivy') {
            steps {
                script {
                    echo "📦 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    try {
                        echo "🔍 Analyse SCA avec Trivy..."
                        sh '''
                            trivy fs --format json --output trivy-reports/sca-report.json . || echo "Trivy SCA avec avertissements"
                            trivy fs --format table --output trivy-reports/sca-report.txt . || echo "Trivy SCA avec avertissements"
                            cp trivy-reports/*.txt security-reports/ || true
                            cp trivy-reports/*.json security-reports/ || true
                        '''
                        echo "✅ Analyse SCA terminée"
                    } catch (Exception e) {
                        echo "❌ Erreur SCA: ${e.message}"
                        error("🛑 PIPELINE ARRÊTÉ - Erreur critique Trivy SCA: ${e.message}")
                    }
                }
            }
        }

        stage('🔍 Quality Gate SCA Trivy') {
            steps {
                script {
                    echo "🔍 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    // [Code du Quality Gate Trivy identique à l'original]
                }
            }
        }

        stage('🐳 Build Docker') {
            steps {
                script {
                    echo "🐳 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    // [Code du Build Docker identique à l'original]
                }
            }
        }

        stage('🔍 Trivy Scan') {
            steps {
                script {
                    echo "🔍 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    // [Code du Trivy Scan identique à l'original]
                }
            }
        }

        stage('🕷️ Analyse DAST avec ZAP') {
            steps {
                script {
                    echo "🕷️ Cette étape ne sera PAS exécutée si SonarQube échoue"
                    // [Code de l'analyse ZAP identique à l'original]
                }
            }
        }

        stage('🔍 Quality Gate OWASP ZAP') {
            steps {
                script {
                    echo "🔍 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    // [Code du Quality Gate ZAP identique à l'original]
                }
            }
        }

        stage('📋 Consolidation des Rapports') {
            steps {
                script {
                    echo "📋 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    // [Code de consolidation identique à l'original]
                }
            }
        }

        stage('🤖 Consultation Mistral AI') {
            steps {
                script {
                    echo "🤖 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    echo "⚠️ Mistral AI ne pourra pas analyser les rapports complets"
                    echo "💡 Pour obtenir l'analyse Mistral AI, corrigez d'abord les problèmes SonarQube"
                    // [Code Mistral AI identique à l'original]
                }
            }
        }

        stage('📊 Generation rapport consolide') {
            steps {
                script {
                    echo "📊 Cette étape ne sera PAS exécutée si SonarQube échoue"
                    // [Code de génération rapport identique à l'original]
                }
            }
        }
    }

    post {
        always {
            echo '🧹 Nettoyage et archivage...'
            archiveArtifacts artifacts: 'security-reports/**/*', allowEmptyArchive: true
            
            script {
                try {
                    // Publier le rapport d'échec si disponible
                    if (fileExists('security-reports/pipeline-failure-report.html')) {
                        try {
                            publishHTML([
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'security-reports',
                                reportFiles: 'pipeline-failure-report.html',
                                reportName: '💥 Rapport Échec Pipeline SonarQube',
                                reportTitles: 'Échec Quality Gate SonarQube'
                            ])
                            echo "📊 Rapport d'échec HTML publié"
                        } catch (Exception e) {
                            echo "⚠️ Plugin HTML non disponible - Rapport dans les artefacts"
                        }
                    }
                } catch (Exception e) {
                    echo "⚠️ Erreur publication HTML: ${e.message}"
                }
            }
            
            sh 'rm -rf sonar-scanner-* *.zip mistral-payload.json TestFile.java || true'
            sh 'docker system prune -f || true'
        }

        success {
            echo '🎉 Pipeline réussi - Tous les Quality Gates passés!'
            echo '⚠️ NOTE: Ce pipeline était configuré pour échouer au SonarQube, mais il a réussi'
            script {
                try {
                    emailext (
                        subject: "🎉 Pipeline Sécurité RÉUSSI (inattendu) - ${JOB_NAME} #${BUILD_NUMBER}",
                        body: """
🎉 PIPELINE SÉCURITÉ RÉUSSI - MAIS CONFIGURATION À VÉRIFIER

🔧 Build: ${BUILD_NUMBER}
📅 Date: ${new Date()}
✅ Statut: SUCCESS

⚠️ ATTENTION: Ce pipeline était configuré pour échouer au Quality Gate SonarQube
mais il a réussi. Vérifiez la configuration:
- FORCE_SONAR_FAILURE était défini à 'true'
- Le serveur SonarQube était-il accessible ?
- Les Quality Gates sont-ils correctement configurés ?

📊 Étapes exécutées avec succès:
✅ Checkout et création de fichiers de test
✅ Analyse SonarQube
✅ Quality Gate SonarQube (inattendu)
✅ Toutes les étapes suivantes

🔍 Vérifiez les logs pour comprendre pourquoi l'échec simulé n'a pas fonctionné.
                        """,
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "⚠️ Erreur email: ${e.message}"
                }
            }
        }

        failure {
            echo '💥 Pipeline échoué - Quality Gate SonarQube comme prévu!'
            script {
                try {
                    emailext (
                        subject: "💥 ÉCHEC ATTENDU - Quality Gate SonarQube - ${JOB_NAME} #${BUILD_NUMBER}",
                        body: """
💥 PIPELINE ARRÊTÉ AU QUALITY GATE SONARQUBE - COMPORTEMENT ATTENDU

🔧 Build: ${BUILD_NUMBER}
📅 Date: ${new Date()}
❌ Statut: FAILURE

🎯 RÉSULTAT ATTENDU: Le pipeline s'est correctement arrêté au Quality Gate SonarQube

✅ Étapes exécutées:
1. ✅ Checkout (fichiers de test créés)
2. ✅ Analyse SonarQube (problèmes détectés)
3. ❌ Quality Gate SonarQube (ÉCHEC SIMULÉ)

❌ Étapes NON exécutées (comme prévu):
- Analyse SCA avec Trivy
- Quality Gate SCA Trivy  
- Build Docker
- Trivy Scan
- Analyse DAST avec ZAP
- Quality Gate OWASP ZAP
- Consolidation des Rapports
- 🤖 Consultation Mistral AI (pas atteinte)

🛡️ SÉCURITÉ: La politique Zero Trust fonctionne correctement
📋 Consultez les rapports détaillés dans Jenkins

🔧 Pour tester le pipeline complet:
1. Définissez FORCE_SONAR_FAILURE = 'false'
2. Corrigez les problèmes de code simulés
3. Relancez le pipeline
                        """,
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "⚠️ Erreur email: ${e.message}"
                }
            }
        }

        unstable {
            echo '⚠️ Pipeline instable'
            script {
                try {
                    emailext (
                        subject: "⚠️ Pipeline INSTABLE - SonarQube - ${JOB_NAME} #${BUILD_NUMBER}",
                        body: """
⚠️ PIPELINE INSTABLE

🔧 Build: ${BUILD_NUMBER}
📅 Date: ${new Date()}
⚠️ Statut: UNSTABLE

Situation inattendue: Le pipeline devait échouer au Quality Gate SonarQube
mais il est dans un état instable. Vérifiez la configuration.

📊 Consultez les logs pour plus de détails.
                        """,
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "⚠️ Erreur email: ${e.message}"
                }
            }
        }
    }
}
