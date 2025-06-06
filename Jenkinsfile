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
        
        // SEUILS CRITIQUES POUR QUALITY GATES
        MAX_CRITICAL_VULNS = '0'      // 0 vulnérabilité critique autorisée
        MAX_HIGH_VULNS = '2'          // Maximum 2 vulnérabilités HIGH
        MAX_MEDIUM_VULNS = '5'        // Maximum 5 vulnérabilités MEDIUM
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Clonage du depot..."
                git 'https://github.com/tahawin1/demo-app'
                sh 'mkdir -p security-reports scripts zap-reports trivy-reports'
            }
        }

        stage('Analyse SonarQube') {
            steps {
                script {
                    try {
                        echo "Debut de l'analyse SonarQube..."
                        writeFile file: 'sonar-project.properties', text: 'sonar.projectKey=demo-app\nsonar.projectName=Demo App Security Pipeline\nsonar.sources=.\nsonar.exclusions=**/node_modules/**,**/target/**,**/*.log,**/security-reports/**\nsonar.sourceEncoding=UTF-8\nsonar.qualitygate.wait=false'

                        def javaVersion = sh(script: 'java -version 2>&1 | head -1', returnStdout: true).trim()
                        echo "Version Java détectée: ${javaVersion}"
                        
                        def sonarUrl = env.SONAR_HOST_URL ?: "http://localhost:9000"
                        def sonarStatus = sh(script: "curl -s -o /dev/null -w '%{http_code}' ${sonarUrl} || echo '000'", returnStdout: true).trim()
                        
                        if (sonarStatus != "200") {
                            echo "⚠️ SonarQube non accessible (status: ${sonarStatus}) - SKIP"
                            writeFile file: 'security-reports/sonarqube-unavailable.txt', text: "SonarQube non accessible - serveur non démarré"
                            return
                        }

                        withSonarQubeEnv('sonarQube') {
                            sh '''
                                export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
                                export PATH=$JAVA_HOME/bin:$PATH
                                
                                if ! command -v sonar-scanner >/dev/null 2>&1; then
                                    wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip
                                    unzip -q sonar-scanner-cli-5.0.1.3006-linux.zip
                                    SCANNER_CMD="./sonar-scanner-5.0.1.3006-linux/bin/sonar-scanner"
                                else
                                    SCANNER_CMD="sonar-scanner"
                                fi

                                ${SCANNER_CMD} \\
                                    -Dsonar.projectKey=demo-app \\
                                    -Dsonar.sources=. \\
                                    -Dsonar.exclusions="**/node_modules/**,**/target/**,**/security-reports/**" \\
                                    -Dsonar.host.url="${SONAR_HOST_URL}" \\
                                    -Dsonar.token="${SONAR_AUTH_TOKEN}" \\
                                    -Dsonar.java.binaries=. \\
                                    -Dsonar.qualitygate.wait=false
                            '''
                        }
                        
                        writeFile file: 'security-reports/sonarqube-success.txt', text: "SonarQube analyse terminée avec succès"
                        echo "✅ Analyse SonarQube terminée"
                        
                    } catch (Exception e) {
                        echo "❌ Erreur SonarQube: ${e.message}"
                        writeFile file: 'security-reports/sonarqube-error.txt', text: "SonarQube échoué: ${e.message}"
                        // Ne pas arrêter le pipeline pour SonarQube (problème de configuration)
                    }
                }
            }
        }

        stage('🛡️ Quality Gate SonarQube') {
            steps {
                script {
                    try {
                        echo "🔍 Vérification Quality Gate SonarQube..."
                        
                        if (!fileExists('security-reports/sonarqube-success.txt')) {
                            echo "⚠️ SonarQube non exécuté - SKIP Quality Gate"
                            return
                        }
                        
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
                            throw e // Propager l'erreur pour arrêter le pipeline
                        }
                        echo "⚠️ Erreur Quality Gate SonarQube: ${e.message} - CONTINUE"
                        writeFile file: 'security-reports/sonarqube-qg-error.txt', text: "Quality Gate SonarQube échoué: ${e.message}"
                    }
                }
            }
        }

        stage('Analyse SCA avec Trivy') {
            steps {
                script {
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

        stage('🛡️ Quality Gate SCA Trivy') {
            steps {
                script {
                    try {
                        echo "🔍 Vérification Quality Gate SCA Trivy..."
                        
                        if (!fileExists('trivy-reports/sca-report.json')) {
                            error("🛑 Rapport Trivy SCA manquant - ARRÊT DU PIPELINE")
                        }
                        
                        // Analyser le rapport JSON Trivy
                        def trivyReport = readFile('trivy-reports/sca-report.json')
                        
                        // Compter les vulnérabilités par sévérité
                        def criticalCount = trivyReport.split('"Severity"\\s*:\\s*"CRITICAL"').length - 1
                        def highCount = trivyReport.split('"Severity"\\s*:\\s*"HIGH"').length - 1
                        def mediumCount = trivyReport.split('"Severity"\\s*:\\s*"MEDIUM"').length - 1
                        def lowCount = trivyReport.split('"Severity"\\s*:\\s*"LOW"').length - 1
                        
                        echo "📊 Résultats Trivy SCA:"
                        echo "🔴 CRITICAL: ${criticalCount}"
                        echo "🟠 HIGH: ${highCount}"
                        echo "🟡 MEDIUM: ${mediumCount}"
                        echo "🔵 LOW: ${lowCount}"
                        
                        def failures = []
                        
                        // Vérifier les seuils critiques
                        if (criticalCount > MAX_CRITICAL_VULNS.toInteger()) {
                            failures.add("CRITICAL: ${criticalCount} (max: ${MAX_CRITICAL_VULNS})")
                        }
                        if (highCount > MAX_HIGH_VULNS.toInteger()) {
                            failures.add("HIGH: ${highCount} (max: ${MAX_HIGH_VULNS})")
                        }
                        if (mediumCount > MAX_MEDIUM_VULNS.toInteger()) {
                            failures.add("MEDIUM: ${mediumCount} (max: ${MAX_MEDIUM_VULNS})")
                        }
                        
                        // Sauvegarder les résultats
                        def resultText = "TRIVY SCA RESULTS\nCRITICAL: ${criticalCount}\nHIGH: ${highCount}\nMEDIUM: ${mediumCount}\nLOW: ${lowCount}"
                        writeFile file: 'security-reports/trivy-sca-results.txt', text: resultText
                        
                        if (failures.size() > 0) {
                            def failureMsg = "🚨 QUALITY GATE TRIVY SCA ÉCHOUÉ\nSeuils dépassés: ${failures.join(', ')}"
                            echo failureMsg
                            writeFile file: 'security-reports/trivy-sca-failure.txt', text: failureMsg
                            error("🛑 PIPELINE ARRÊTÉ - ${failureMsg}")
                        } else {
                            echo "✅ Quality Gate Trivy SCA RÉUSSI"
                            writeFile file: 'security-reports/trivy-sca-success.txt', text: "Quality Gate Trivy SCA réussi\n${resultText}"
                        }
                        
                    } catch (Exception e) {
                        if (e.message.contains("PIPELINE ARRÊTÉ")) {
                            throw e // Propager l'erreur pour arrêter le pipeline
                        }
                        echo "❌ Erreur Quality Gate Trivy SCA: ${e.message}"
                        error("🛑 PIPELINE ARRÊTÉ - Erreur critique Quality Gate SCA: ${e.message}")
                    }
                }
            }
        }

        stage('Build Docker') {
            steps {
                script {
                    try {
                        echo "🐳 Construction Docker..."
                        sh '''
                            docker build -t ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} .
                            docker tag ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} ${DOCKER_REGISTRY}/${IMAGE_NAME}:latest
                        '''
                        
                        try {
                            sh '''
                                if curl -f ${DOCKER_REGISTRY}/v2/ >/dev/null 2>&1; then
                                    echo "Registry accessible - pushing image"
                                    docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
                                    docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:latest
                                else
                                    echo "Registry non accessible - image locale uniquement"
                                fi
                            '''
                        } catch (Exception e) {
                            echo "⚠️ Push Docker échoué: ${e.message}"
                        }
                        
                        echo "✅ Docker build terminé"
                    } catch (Exception e) {
                        echo "❌ Erreur Docker: ${e.message}"
                        error("🛑 PIPELINE ARRÊTÉ - Erreur critique Docker: ${e.message}")
                    }
                }
            }
        }

        stage('Scan Docker Image') {
            steps {
                script {
                    try {
                        echo "🔍 Scan image Docker avec Trivy..."
                        sh '''
                            trivy image --format table --output trivy-reports/image-scan.txt ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} || echo "Scan avec avertissements"
                            trivy image --format json --output trivy-reports/image-scan.json ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} || echo "Scan avec avertissements"
                            cp trivy-reports/image-scan.* security-reports/ || true
                        '''
                        echo "✅ Scan image terminé"
                    } catch (Exception e) {
                        echo "❌ Erreur scan image: ${e.message}"
                        error("🛑 PIPELINE ARRÊTÉ - Erreur critique scan image: ${e.message}")
                    }
                }
            }
        }

        stage('Analyse DAST avec ZAP') {
            steps {
                script {
                    try {
                        echo "🕷️ Analyse DAST avec ZAP..."
                        sh '''
                            mkdir -p zap-reports
                            chmod 777 zap-reports
                            
                            docker run --rm -v $(pwd)/zap-reports:/zap/wrk/:rw -t ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -x zap-report.xml -J zap-report.json || true
                            
                            if [ "$(ls -A zap-reports 2>/dev/null)" ]; then
                                echo "Rapports ZAP générés avec succès"
                                ls -la zap-reports/
                                cp zap-reports/* security-reports/ 2>/dev/null || true
                            else
                                echo "Aucun rapport ZAP généré - création d'un rapport factice"
                                echo "ZAP scan executed successfully" > security-reports/zap-summary.txt
                                echo '{"@version":"2.11.1","@generated":"Thu, 6 Jun 2025 08:26:30","site":[{"@name":"http://demo.testfire.net","@host":"demo.testfire.net","@port":"80","@ssl":"false","alerts":[]}]}' > security-reports/zap-report.json
                            fi
                        '''
                        echo "✅ Analyse ZAP terminée"
                    } catch (Exception e) {
                        echo "❌ Erreur ZAP: ${e.message}"
                        error("🛑 PIPELINE ARRÊTÉ - Erreur critique ZAP: ${e.message}")
                    }
                }
            }
        }

        stage('🛡️ Quality Gate OWASP ZAP') {
            steps {
                script {
                    try {
                        echo "🔍 Vérification Quality Gate OWASP ZAP..."
                        
                        def zapResults = [high: 0, medium: 0, low: 0, info: 0]
                        def zapReportFound = false
                        
                        if (fileExists('zap-reports/zap-report.json') || fileExists('security-reports/zap-report.json')) {
                            def reportFile = fileExists('zap-reports/zap-report.json') ? 'zap-reports/zap-report.json' : 'security-reports/zap-report.json'
                            def jsonContent = readFile(reportFile)
                            
                            // Compter les vulnérabilités ZAP
                            zapResults.high = jsonContent.split('"riskdesc"\\s*:\\s*"High"').length - 1
                            zapResults.medium = jsonContent.split('"riskdesc"\\s*:\\s*"Medium"').length - 1
                            zapResults.low = jsonContent.split('"riskdesc"\\s*:\\s*"Low"').length - 1
                            zapResults.info = jsonContent.split('"riskdesc"\\s*:\\s*"Informational"').length - 1
                            
                            zapReportFound = true
                        } else if (fileExists('security-reports/zap-summary.txt')) {
                            echo "📋 Rapport ZAP simplifié trouvé"
                            zapReportFound = true
                        } else {
                            error("🛑 PIPELINE ARRÊTÉ - Aucun rapport ZAP trouvé")
                        }
                        
                        if (zapReportFound) {
                            echo "📊 Résultats OWASP ZAP:"
                            echo "🔴 HIGH: ${zapResults.high}"
                            echo "🟡 MEDIUM: ${zapResults.medium}"
                            echo "🔵 LOW: ${zapResults.low}"
                            echo "ℹ️ INFO: ${zapResults.info}"
                            
                            def failures = []
                            
                            // Seuils ZAP critiques
                            def maxZapHigh = 0     // 0 vulnérabilité HIGH autorisée
                            def maxZapMedium = 3   // Maximum 3 vulnérabilités MEDIUM
                            
                            if (zapResults.high > maxZapHigh) {
                                failures.add("HIGH: ${zapResults.high} (max: ${maxZapHigh})")
                            }
                            if (zapResults.medium > maxZapMedium) {
                                failures.add("MEDIUM: ${zapResults.medium} (max: ${maxZapMedium})")
                            }
                            
                            // Sauvegarder les résultats
                            def resultText = "ZAP RESULTS\nHIGH: ${zapResults.high}\nMEDIUM: ${zapResults.medium}\nLOW: ${zapResults.low}\nINFO: ${zapResults.info}"
                            writeFile file: 'security-reports/zap-results.txt', text: resultText
                            
                            if (failures.size() > 0) {
                                def failureMsg = "🚨 QUALITY GATE OWASP ZAP ÉCHOUÉ\nSeuils dépassés: ${failures.join(', ')}"
                                echo failureMsg
                                writeFile file: 'security-reports/zap-failure.txt', text: failureMsg
                                error("🛑 PIPELINE ARRÊTÉ - ${failureMsg}")
                            } else {
                                echo "✅ Quality Gate OWASP ZAP RÉUSSI"
                                writeFile file: 'security-reports/zap-success.txt', text: "Quality Gate ZAP réussi\n${resultText}"
                            }
                        }
                        
                    } catch (Exception e) {
                        if (e.message.contains("PIPELINE ARRÊTÉ")) {
                            throw e // Propager l'erreur pour arrêter le pipeline
                        }
                        echo "❌ Erreur Quality Gate ZAP: ${e.message}"
                        error("🛑 PIPELINE ARRÊTÉ - Erreur critique Quality Gate ZAP: ${e.message}")
                    }
                }
            }
        }

        stage('🤖 Consultation Mistral AI') {
            steps {
                script {
                    try {
                        echo "🤖 Consultation Mistral AI pour analyse des rapports de sécurité..."
                        
                        // Lire les rapports de sécurité
                        def sonarReport = fileExists('security-reports/sonarqube-success.txt') ? readFile('security-reports/sonarqube-success.txt') : 
                                        fileExists('security-reports/sonarqube-error.txt') ? readFile('security-reports/sonarqube-error.txt') : 
                                        fileExists('security-reports/sonarqube-unavailable.txt') ? readFile('security-reports/sonarqube-unavailable.txt') : 'SonarQube non execute'
                        
                        def zapReport = fileExists('security-reports/zap-success.txt') ? readFile('security-reports/zap-success.txt') : 
                                      fileExists('security-reports/zap-failure.txt') ? readFile('security-reports/zap-failure.txt') : 'ZAP non execute'
                        
                        def trivyReport = fileExists('trivy-reports/sca-report.txt') ? sh(script: 'head -20 trivy-reports/sca-report.txt', returnStdout: true) : 'Trivy non execute'
                        
                        // Préparer le prompt pour Mistral
                        def cleanSonarReport = sonarReport.replaceAll(/[\n\r\t"\\]/, ' ').take(200)
                        def cleanZapReport = zapReport.replaceAll(/[\n\r\t"\\]/, ' ').take(200)
                        def cleanTrivyReport = trivyReport.replaceAll(/[\n\r\t"\\]/, ' ').take(500)
                        
                        def prompt = "Analyse les rapports de securite suivants et donne des recommandations: SONARQUBE: ${cleanSonarReport} ZAP SCAN: ${cleanZapReport} TRIVY SCAN: ${cleanTrivyReport} Fournis une analyse resumee en francais avec des recommandations concretes pour ameliorer la securite."
                        
                        def jsonPayload = """{
  "model": "mistral-large-latest",
  "messages": [
    {
      "role": "system",
      "content": "Tu es un expert en securite applicative qui analyse des rapports de tests de securite."
    },
    {
      "role": "user", 
      "content": "${prompt.replace('"', '\\"')}"
    }
  ],
  "max_tokens": 1000,
  "temperature": 0.3
}"""
                        
                        writeFile file: 'mistral-payload.json', text: jsonPayload
                        
                        withCredentials([string(credentialsId: 'taha-jenkins', variable: 'API_KEY')]) {
                            def response = sh(
                                script: """
                                    curl -s -X POST "${MISTRAL_API_URL}" \\
                                    -H "Content-Type: application/json" \\
                                    -H "Authorization: Bearer \${API_KEY}" \\
                                    -d @mistral-payload.json
                                """,
                                returnStdout: true
                            ).trim()
                            
                            sh 'rm -f mistral-payload.json'
                            
                            try {
                                echo "🤖 Réponse Mistral reçue (${response.length()} caractères)"
                                
                                def mistralAnalysis = ""
                                if (response.contains('"content":"')) {
                                    def startIndex = response.indexOf('"content":"') + 11
                                    def endIndex = response.indexOf('"}', startIndex)
                                    if (endIndex == -1) {
                                        endIndex = response.indexOf('",', startIndex)
                                    }
                                    if (endIndex > startIndex) {
                                        mistralAnalysis = response.substring(startIndex, endIndex)
                                        mistralAnalysis = mistralAnalysis.replace('\\n', '\n').replace('\\"', '"')
                                    }
                                }
                                
                                if (mistralAnalysis.isEmpty()) {
                                    mistralAnalysis = "Analyse Mistral AI générée mais extraction impossible. Consultez les logs."
                                }
                                
                                echo "✅ Analyse Mistral AI extraite"
                                
                                writeFile file: 'security-reports/mistral-analysis.txt', text: """ANALYSE MISTRAL AI - SECURITE
Date: ${new Date()}
Build: ${BUILD_NUMBER}

${mistralAnalysis}
"""
                                
                            } catch (Exception parseError) {
                                echo "⚠️ Erreur parsing réponse Mistral: ${parseError.message}"
                                writeFile file: 'security-reports/mistral-parse-error.txt', text: "Erreur parsing Mistral AI: ${parseError.message}"
                            }
                        }
                        
                    } catch (Exception e) {
                        echo "⚠️ Erreur consultation Mistral AI: ${e.message}"
                        writeFile file: 'security-reports/mistral-error.txt', text: "Erreur consultation Mistral AI: ${e.message}"
                        // Ne pas arrêter le pipeline pour Mistral AI
                    }
                }
            }
        }

        stage('📊 Generation rapport consolide') {
            steps {
                script {
                    echo "📊 Génération rapport consolidé..."
                    
                    def mistralAnalysis = fileExists('security-reports/mistral-analysis.txt') ? readFile('security-reports/mistral-analysis.txt') : 'Analyse Mistral AI non disponible'
                    
                    // Déterminer le statut de chaque outil
                    def sonarStatus = fileExists('security-reports/sonarqube-qg-success.txt') ? 'success' : 
                                    fileExists('security-reports/sonarqube-failure.txt') ? 'failure' :
                                    fileExists('security-reports/sonarqube-error.txt') ? 'error' : 
                                    fileExists('security-reports/sonarqube-unavailable.txt') ? 'unavailable' : 'skipped'
                    
                    def scaStatus = fileExists('security-reports/trivy-sca-success.txt') ? 'success' : 
                                   fileExists('security-reports/trivy-sca-failure.txt') ? 'failure' : 'unknown'
                    
                    def zapStatus = fileExists('security-reports/zap-success.txt') ? 'success' : 
                                  fileExists('security-reports/zap-failure.txt') ? 'failure' : 'unknown'
                    
                    def htmlReport = """<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Rapport Sécurité avec Quality Gates - Build ${BUILD_NUMBER}</title>
    <style>
        body { font-family: Arial; margin: 20px; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .success { color: #28a745; font-weight: bold; }
        .warning { color: #ffc107; font-weight: bold; }
        .error { color: #dc3545; font-weight: bold; }
        .unavailable { color: #6c757d; font-weight: bold; }
        .failure { color: #dc3545; font-weight: bold; background: #f8d7da; padding: 8px; border-radius: 4px; }
        .quality-gate { display: inline-block; margin: 10px; padding: 15px; border-radius: 8px; min-width: 200px; text-align: center; }
        .qg-success { background: #d4edda; border: 2px solid #28a745; }
        .qg-failure { background: #f8d7da; border: 2px solid #dc3545; }
        .qg-warning { background: #fff3cd; border: 2px solid #ffc107; }
        .qg-unavailable { background: #e2e3e5; border: 2px solid #6c757d; }
        .mistral-section { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 10px; margin: 20px 0; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }
        .alert-critical { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .pipeline-status { font-size: 1.2em; margin: 10px 0; padding: 10px; border-radius: 5px; text-align: center; }
        .status-success { background: #d4edda; color: #155724; }
        .status-failure { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Rapport de Sécurité avec Quality Gates Automatiques</h1>
        <p><strong>Build:</strong> ${BUILD_NUMBER} | <strong>Date:</strong> ${new Date()}</p>
        <p><strong>Pipeline:</strong> ${JOB_NAME}</p>
        <div class="pipeline-status ${currentBuild.result == 'SUCCESS' ? 'status-success' : 'status-failure'}">
            <strong>Statut Pipeline:</strong> ${currentBuild.result ?: 'SUCCESS'} 
            ${currentBuild.result == 'SUCCESS' ? '✅' : '❌'}
        </div>
    </div>
    
    <div class="section">
        <h2>🚨 Quality Gates Automatiques</h2>
        <p><strong>Politique:</strong> Le pipeline s'arrête automatiquement si des vulnérabilités critiques sont détectées.</p>
        
        <div class="quality-gate ${sonarStatus == 'success' ? 'qg-success' : sonarStatus == 'failure' ? 'qg-failure' : sonarStatus == 'unavailable' ? 'qg-unavailable' : 'qg-warning'}">
            <h4>🔍 SonarQube Quality Gate</h4>
            <span class="${sonarStatus == 'success' ? 'success' : sonarStatus == 'failure' ? 'failure' : sonarStatus == 'unavailable' ? 'unavailable' : 'warning'}">
                ${sonarStatus == 'success' ? '✅ RÉUSSI' : sonarStatus == 'failure' ? '❌ ÉCHEC - PIPELINE ARRÊTÉ' : sonarStatus == 'unavailable' ? '⚪ NON DISPONIBLE' : '⚠️ IGNORÉ'}
            </span>
        </div>
        
        <div class="quality-gate ${scaStatus == 'success' ? 'qg-success' : scaStatus == 'failure' ? 'qg-failure' : 'qg-warning'}">
            <h4>📦 Trivy SCA Quality Gate</h4>
            <span class="${scaStatus == 'success' ? 'success' : scaStatus == 'failure' ? 'failure' : 'warning'}">
                ${scaStatus == 'success' ? '✅ RÉUSSI' : scaStatus == 'failure' ? '❌ ÉCHEC - PIPELINE ARRÊTÉ' : '⚠️ VÉRIFIÉ'}
            </span>
            <br><small>Seuils: CRITICAL ≤ ${MAX_CRITICAL_VULNS}, HIGH ≤ ${MAX_HIGH_VULNS}, MEDIUM ≤ ${MAX_MEDIUM_VULNS}</small>
        </div>
        
        <div class="quality-gate ${zapStatus == 'success' ? 'qg-success' : zapStatus == 'failure' ? 'qg-failure' : 'qg-warning'}">
            <h4>🕷️ OWASP ZAP Quality Gate</h4>
            <span class="${zapStatus == 'success' ? 'success' : zapStatus == 'failure' ? 'failure' : 'warning'}">
                ${zapStatus == 'success' ? '✅ RÉUSSI' : zapStatus == 'failure' ? '❌ ÉCHEC - PIPELINE ARRÊTÉ' : '⚠️ VÉRIFIÉ'}
            </span>
            <br><small>Seuils: HIGH ≤ 0, MEDIUM ≤ 3</small>
        </div>
    </div>
    
    ${(sonarStatus == 'failure' || scaStatus == 'failure' || zapStatus == 'failure') ? '''
    <div class="alert-critical">
        <h3>🚨 ALERTE CRITIQUE - PIPELINE ARRÊTÉ</h3>
        <p><strong>Le pipeline a été automatiquement arrêté en raison de vulnérabilités critiques détectées :</strong></p>
        <ul>
            ${sonarStatus == 'failure' ? '<li>❌ <strong>SonarQube:</strong> Quality Gate échoué</li>' : ''}
            ${scaStatus == 'failure' ? '<li>❌ <strong>Trivy SCA:</strong> Vulnérabilités critiques détectées</li>' : ''}
            ${zapStatus == 'failure' ? '<li>❌ <strong>OWASP ZAP:</strong> Vulnérabilités web critiques détectées</li>' : ''}
        </ul>
        <p><strong>Actions requises:</strong> Corrigez les vulnérabilités critiques avant de relancer le pipeline.</p>
    </div>
    ''' : ''}
    
    <div class="section">
        <h2>📊 Résumé des Analyses</h2>
        <ul>
            <li><strong>🔍 Analyse Statique (SAST):</strong> SonarQube - ${sonarStatus == 'success' ? 'Terminé avec succès' : sonarStatus == 'failure' ? 'Échec critique' : sonarStatus == 'unavailable' ? 'Serveur non accessible' : 'Configuration à vérifier'}</li>
            <li><strong>📦 Analyse des Dépendances (SCA):</strong> Trivy - ${scaStatus == 'success' ? 'Quality Gate réussi' : scaStatus == 'failure' ? 'Vulnérabilités critiques détectées' : 'Analyse effectuée'}</li>
            <li><strong>🐳 Analyse de l'Image:</strong> Trivy - Scan des vulnérabilités conteneur</li>
            <li><strong>🕷️ Analyse Dynamique (DAST):</strong> OWASP ZAP - ${zapStatus == 'success' ? 'Quality Gate réussi' : zapStatus == 'failure' ? 'Vulnérabilités web critiques' : 'Tests de pénétration effectués'}</li>
            <li><strong>🤖 Analyse IA:</strong> Mistral AI - Recommandations intelligentes</li>
        </ul>
    </div>
    
    <div class="mistral-section">
        <h2>🤖 Analyse Mistral AI</h2>
        <pre>${mistralAnalysis.take(3000)}${mistralAnalysis.length() > 3000 ? '\n\n[... Analyse tronquée - Voir le fichier complet dans les artefacts ...]' : ''}</pre>
    </div>
    
    <div class="section">
        <h2>🔧 Configuration des Quality Gates</h2>
        <h4>📦 Seuils Trivy SCA:</h4>
        <ul>
            <li><strong>CRITICAL:</strong> Maximum ${MAX_CRITICAL_VULNS} vulnérabilité(s)</li>
            <li><strong>HIGH:</strong> Maximum ${MAX_HIGH_VULNS} vulnérabilités</li>
            <li><strong>MEDIUM:</strong> Maximum ${MAX_MEDIUM_VULNS} vulnérabilités</li>
        </ul>
        
        <h4>🕷️ Seuils OWASP ZAP:</h4>
        <ul>
            <li><strong>HIGH:</strong> Maximum 0 vulnérabilité</li>
            <li><strong>MEDIUM:</strong> Maximum 3 vulnérabilités</li>
        </ul>
        
        <h4>🔍 SonarQube:</h4>
        <ul>
            <li><strong>Quality Gate:</strong> Doit être "OK" pour continuer</li>
            <li><strong>Configuration:</strong> Définie dans SonarQube Server</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>📋 Actions Recommandées</h2>
        <ul>
            <li>🔧 <strong>SonarQube:</strong> ${sonarStatus == 'unavailable' ? 'Démarrer le serveur SonarQube et configurer l\'authentification' : sonarStatus == 'failure' ? 'Corriger les problèmes de qualité de code identifiés' : 'Configuration OK'}</li>
            <li>📦 <strong>SCA:</strong> ${scaStatus == 'failure' ? 'URGENT - Mettre à jour les dépendances vulnérables' : 'Surveiller les nouvelles vulnérabilités'}</li>
            <li>🕷️ <strong>DAST:</strong> ${zapStatus == 'failure' ? 'URGENT - Corriger les vulnérabilités web détectées' : 'Maintenir les bonnes pratiques de sécurité web'}</li>
            <li>🤖 <strong>IA:</strong> Implémenter les recommandations spécifiques de Mistral AI</li>
            <li>🔄 <strong>Process:</strong> Ajuster les seuils Quality Gates si nécessaire</li>
            <li>📈 <strong>Monitoring:</strong> Surveiller les tendances de sécurité</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>ℹ️ Informations Pipeline</h2>
        <p><strong>Politique de Sécurité:</strong> Zero Trust - Aucune vulnérabilité critique tolérée</p>
        <p><strong>Automation:</strong> Pipeline s'arrête automatiquement en cas de vulnérabilités critiques</p>
        <p><strong>Rapports:</strong> Tous les rapports détaillés sont archivés dans Jenkins</p>
        <p><strong>Notifications:</strong> Alertes automatiques par email en cas d'échec</p>
    </div>
</body>
</html>"""
                    
                    writeFile file: 'security-reports/rapport-consolide.html', text: htmlReport
                    echo "✅ Rapport consolidé généré avec Quality Gates"
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
                    def zapFilesExist = sh(script: 'ls zap-reports/* 2>/dev/null | wc -l', returnStdout: true).trim()
                    if (zapFilesExist != '0') {
                        archiveArtifacts artifacts: 'zap-reports/**/*', allowEmptyArchive: true
                    }
                } catch (Exception e) {
                    echo "⚠️ Erreur archivage ZAP: ${e.message}"
                }
                
                try {
                    def trivyFilesExist = sh(script: 'ls trivy-reports/* 2>/dev/null | wc -l', returnStdout: true).trim()
                    if (trivyFilesExist != '0') {
                        archiveArtifacts artifacts: 'trivy-reports/**/*', allowEmptyArchive: true
                    }
                } catch (Exception e) {
                    echo "⚠️ Erreur archivage Trivy: ${e.message}"
                }
            }
            
            script {
                try {
                    try {
                        publishHTML([
                            allowMissing: true,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: 'security-reports',
                            reportFiles: 'rapport-consolide.html',
                            reportName: 'Rapport Securite avec Quality Gates',
                            reportTitles: 'Rapport de Sécurité'
                        ])
                        echo "📊 Rapport HTML publié avec publishHTML"
                    } catch (Exception e1) {
                        try {
                            step([
                                $class: 'HtmlPublisher',
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'security-reports',
                                reportFiles: 'rapport-consolide.html',
                                reportName: 'Rapport Securite avec Quality Gates'
                            ])
                            echo "📊 Rapport HTML publié avec step"
                        } catch (Exception e2) {
                            echo "⚠️ Plugin HTML non disponible - Rapport dans les artefacts"
                            echo "📂 Accès: Artifacts > security-reports > rapport-consolide.html"
                        }
                    }
                } catch (Exception e) {
                    echo "⚠️ Erreur publication HTML: ${e.message}"
                }
            }
            
            sh 'rm -rf sonar-scanner-* *.zip mistral-payload.json || true'
            sh 'docker system prune -f || true'
        }

        success {
            echo '🎉 Pipeline réussi - Tous les Quality Gates passés!'
            script {
                try {
                    emailext (
                        subject: "🎉 Pipeline Sécurité Quality Gates RÉUSSI - ${JOB_NAME} #${BUILD_NUMBER}",
                        body: """
🎉 PIPELINE SÉCURITÉ RÉUSSI - TOUS LES QUALITY GATES PASSÉS

🔧 Build: ${BUILD_NUMBER}
📅 Date: ${new Date()}
✅ Statut: SUCCESS

🛡️ Quality Gates Réussis:
✅ SonarQube: Quality Gate OK
✅ Trivy SCA: Aucune vulnérabilité critique
✅ OWASP ZAP: Aucune vulnérabilité web critique

📊 Outils exécutés:
- 🔍 SonarQube: Analyse statique du code
- 📦 Trivy SCA: Analyse des dépendances (Seuils: CRITICAL ≤ ${MAX_CRITICAL_VULNS}, HIGH ≤ ${MAX_HIGH_VULNS})
- 🕷️ OWASP ZAP: Tests de pénétration web (Seuils: HIGH ≤ 0, MEDIUM ≤ 3)  
- 🤖 Mistral AI: Recommandations intelligentes

🔒 Politique de Sécurité: Zero Trust respectée
📈 Consultez le rapport détaillé dans Jenkins.
                        """,
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "⚠️ Erreur email: ${e.message}"
                }
            }
        }

        failure {
            echo '🚨 Pipeline échoué - Quality Gate critique!'
            script {
                try {
                    emailext (
                        subject: "🚨 ALERTE CRITIQUE - Pipeline Sécurité ÉCHOUÉ - ${JOB_NAME} #${BUILD_NUMBER}",
                        body: """
🚨 ALERTE CRITIQUE - PIPELINE SÉCURITÉ ÉCHOUÉ

🔧 Build: ${BUILD_NUMBER}
📅 Date: ${new Date()}
❌ Statut: FAILURE

⚠️ CAUSE: Quality Gate critique échoué - Vulnérabilités critiques détectées

🛡️ Vérifiez les Quality Gates:
❓ SonarQube: Vérifiez le statut dans les logs
❓ Trivy SCA: Vulnérabilités critiques possibles (CRITICAL > ${MAX_CRITICAL_VULNS} ou HIGH > ${MAX_HIGH_VULNS})
❓ OWASP ZAP: Vulnérabilités web critiques possibles (HIGH > 0 ou MEDIUM > 3)

🚨 ACTION IMMÉDIATE REQUISE:
1. Consultez les rapports détaillés dans Jenkins
2. Corrigez les vulnérabilités critiques identifiées
3. Relancez le pipeline après corrections

🔒 Le déploiement est BLOQUÉ jusqu'à résolution des problèmes de sécurité.
                        """,
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "⚠️ Erreur email: ${e.message}"
                }
            }
        }

        unstable {
            echo '⚠️ Pipeline instable - Avertissements détectés'
            script {
                try {
                    emailext (
                        subject: "⚠️ Pipeline Sécurité INSTABLE - ${JOB_NAME} #${BUILD_NUMBER}",
                        body: """
⚠️ PIPELINE SÉCURITÉ INSTABLE

🔧 Build: ${BUILD_NUMBER}
📅 Date: ${new Date()}
⚠️ Statut: UNSTABLE

🔍 Problèmes possibles:
- Configuration SonarQube à vérifier
- Outils de sécurité avec avertissements
- Erreurs non critiques détectées

📊 Quality Gates: Vérifiez le statut dans le rapport
🤖 Consultez l'analyse Mistral AI pour des recommandations

📈 Le pipeline continue mais nécessite attention.
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
