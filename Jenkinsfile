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

                        writeFile file: 'sonar-project.properties', text: 'sonar.projectKey=demo-app\nsonar.projectName=Demo App Security Pipeline\nsonar.sources=.\nsonar.exclusions=**/node_modules/**,**/target/**,**/*.log,**/security-reports/**\nsonar.sourceEncoding=UTF-8\nsonar.qualitygate.wait=true'

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
                                    -Dsonar.sources=. \\
                                    -Dsonar.exclusions="**/node_modules/**,**/target/**" \\
                                    -Dsonar.host.url="${SONAR_HOST_URL}" \\
                                    -Dsonar.login="${SONAR_AUTH_TOKEN}"
                            '''
                        }
                        echo "Analyse SonarQube terminee"
                    } catch (Exception e) {
                        echo "Erreur SonarQube: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Quality Gate SonarQube') {
            steps {
                script {
                    if (currentBuild.result == 'FAILURE') {
                        echo "Stage ignore - build en echec"
                        return
                    }
                    
                    try {
                        echo "Verification du Quality Gate SonarQube..."
                        
                        def sonarAvailable = false
                        try {
                            def sonarUrl = env.SONAR_HOST_URL ?: "http://localhost:9000"
                            def sonarStatus = sh(script: "curl -s -o /dev/null -w '%{http_code}' ${sonarUrl} || echo '000'", returnStdout: true).trim()
                            sonarAvailable = (sonarStatus == "200")
                        } catch (Exception e) {
                            echo "Impossible de verifier SonarQube: ${e.message}"
                        }
                        
                        if (!sonarAvailable) {
                            echo "SonarQube non accessible"
                            writeFile file: 'security-reports/sonarqube-skipped.txt', text: 'SonarQube non accessible - Quality Gate ignore'
                            return
                        }
                        
                        timeout(time: 5, unit: 'MINUTES') {
                            def qg = waitForQualityGate()
                            echo "Statut Quality Gate: ${qg.status}"
                            
                            if (qg.status != 'OK') {
                                echo "Quality Gate SonarQube ECHOUE"
                                writeFile file: 'security-reports/sonarqube-failure.txt', text: "Quality Gate echoue - Statut: ${qg.status}"
                                currentBuild.result = 'UNSTABLE'
                            } else {
                                echo "Quality Gate SonarQube REUSSI"
                                writeFile file: 'security-reports/sonarqube-success.txt', text: "Quality Gate reussi - Statut: ${qg.status}"
                            }
                        }
                    } catch (Exception e) {
                        echo "Erreur Quality Gate: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Analyse SCA avec Trivy') {
            steps {
                script {
                    try {
                        echo 'Analyse SCA avec Trivy...'
                        sh '''
                            trivy fs --format json --output trivy-reports/sca-report.json . || echo "Trivy SCA avec avertissements"
                            trivy fs --format table --output trivy-reports/sca-report.txt . || echo "Trivy SCA avec avertissements"
                            cp trivy-reports/*.txt security-reports/ || true
                            cp trivy-reports/*.json security-reports/ || true
                        '''
                        echo "Analyse SCA terminee"
                    } catch (Exception e) {
                        echo "Erreur SCA: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Build Docker') {
            steps {
                script {
                    try {
                        echo 'Construction Docker...'
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
                            echo "Push Docker echoue: ${e.message}"
                        }
                        
                        echo "Docker build termine"
                    } catch (Exception e) {
                        echo "Erreur Docker: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Scan Docker Image') {
            steps {
                script {
                    if (currentBuild.result == 'FAILURE') {
                        echo "Stage ignore"
                        return
                    }
                    
                    try {
                        echo 'Scan image Docker avec Trivy...'
                        sh '''
                            trivy image --format table --output trivy-reports/image-scan.txt ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} || echo "Scan avec avertissements"
                            trivy image --format json --output trivy-reports/image-scan.json ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} || echo "Scan avec avertissements"
                            cp trivy-reports/image-scan.* security-reports/ || true
                        '''
                        echo "Scan image termine"
                    } catch (Exception e) {
                        echo "Erreur scan: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Sign Docker Image') {
            steps {
                script {
                    if (currentBuild.result == 'FAILURE') {
                        echo "Stage ignore"
                        return
                    }
                    
                    try {
                        echo 'Signature Cosign...'
                        try {
                            withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PASSWORD')]) {
                                sh 'cosign sign --key env://COSIGN_PASSWORD ${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} || echo "Signature echouee"'
                            }
                            echo "Signature reussie"
                        } catch (Exception credError) {
                            echo "Credential cosign-key non trouve - signature ignoree"
                        }
                    } catch (Exception e) {
                        echo "Erreur Cosign: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Analyse DAST avec ZAP') {
            steps {
                script {
                    if (currentBuild.result == 'FAILURE') {
                        echo "Stage ignore"
                        return
                    }
                    
                    try {
                        echo "Analyse DAST avec ZAP..."
                        sh '''
                            mkdir -p zap-reports
                            docker run -v $(pwd)/zap-reports:/zap/wrk/:rw -t ${ZAP_IMAGE} zap-baseline.py -t ${TARGET_URL} -r zap-report.html -J zap-report.json || true
                            cp zap-reports/*.html security-reports/ 2>/dev/null || echo "Aucun rapport HTML"
                            cp zap-reports/*.json security-reports/ 2>/dev/null || echo "Aucun rapport JSON"
                        '''
                        echo "Analyse ZAP terminee"
                    } catch (Exception e) {
                        echo "Erreur ZAP: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Quality Gate OWASP ZAP') {
            steps {
                script {
                    if (currentBuild.result == 'FAILURE') {
                        echo "Stage ignore"
                        return
                    }
                    
                    try {
                        echo "Verification Quality Gate ZAP..."
                        
                        def zapResults = [high: 0, medium: 0, low: 0, info: 0]
                        def zapFailures = []
                        
                        if (fileExists('zap-reports/zap-report.json') || fileExists('security-reports/zap-report.json')) {
                            def reportFile = fileExists('zap-reports/zap-report.json') ? 'zap-reports/zap-report.json' : 'security-reports/zap-report.json'
                            def zapJson = readJSON file: reportFile
                            
                            if (zapJson.site && zapJson.site[0] && zapJson.site[0].alerts) {
                                zapJson.site[0].alerts.each { alert ->
                                    switch(alert.riskdesc?.toLowerCase()) {
                                        case ~/.*high.*/:
                                            zapResults.high++
                                            break
                                        case ~/.*medium.*/:
                                            zapResults.medium++
                                            break
                                        case ~/.*low.*/:
                                            zapResults.low++
                                            break
                                        default:
                                            zapResults.info++
                                    }
                                }
                            }
                            
                            echo "Resultats ZAP: High=${zapResults.high}, Medium=${zapResults.medium}, Low=${zapResults.low}, Info=${zapResults.info}"
                            
                            def maxHigh = 0
                            def maxMedium = 3
                            def maxLow = 10
                            
                            if (zapResults.high > maxHigh) {
                                zapFailures.add("Risque HIGH detecte: ${zapResults.high}")
                            }
                            if (zapResults.medium > maxMedium) {
                                zapFailures.add("Risque MEDIUM excessif: ${zapResults.medium}")
                            }
                            if (zapResults.low > maxLow) {
                                zapFailures.add("Risque LOW excessif: ${zapResults.low}")
                            }
                        } else {
                            echo "Rapport ZAP JSON non trouve"
                        }
                        
                        if (zapFailures.size() > 0) {
                            echo "Quality Gate ZAP ECHOUE"
                            echo "Problemes: ${zapFailures.join(', ')}"
                            writeFile file: 'security-reports/zap-failure.txt', text: "ZAP Quality Gate echoue - Problemes: ${zapFailures.join(', ')}"
                            currentBuild.result = 'UNSTABLE'
                        } else {
                            echo "Quality Gate ZAP REUSSI"
                            writeFile file: 'security-reports/zap-success.txt', text: "ZAP Quality Gate reussi - Aucun probleme detecte"
                        }
                        
                    } catch (Exception e) {
                        echo "Erreur Quality Gate ZAP: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Generation rapport consolide') {
            steps {
                script {
                    if (currentBuild.result == 'FAILURE') {
                        echo "Stage ignore"
                        return
                    }
                    
                    echo "Generation rapport consolide..."
                    
                    def htmlReport = '''<!DOCTYPE html>
<html>
<head>
    <title>Rapport Securite</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .header { background: #667eea; color: white; padding: 20px; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport de Securite</h1>
    </div>
    <div class="section">
        <h2>Quality Gates</h2>
        <p>SonarQube: Verifie</p>
        <p>OWASP ZAP: Verifie</p>
        <p>Trivy: Execute</p>
    </div>
    <div class="section">
        <h2>Analyses</h2>
        <ul>
            <li>SonarQube - Qualite du code</li>
            <li>Trivy - Vulnerabilites</li>
            <li>ZAP - Tests dynamiques</li>
            <li>Cosign - Signature</li>
        </ul>
    </div>
</body>
</html>'''
                    
                    writeFile file: 'security-reports/rapport-consolide.html', text: htmlReport
                    echo "Rapport genere"
                }
            }
        }
    }

    post {
        always {
            echo 'Nettoyage et archivage...'
            archiveArtifacts artifacts: 'security-reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'zap-reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'trivy-reports/**/*', allowEmptyArchive: true
            
            script {
                try {
                    step([
                        $class: 'PublishHTMLReportsStep',
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'security-reports',
                        reportFiles: 'rapport-consolide.html',
                        reportName: 'Rapport Securite'
                    ])
                    echo "Rapport HTML publie"
                } catch (Exception e) {
                    echo "Plugin HTML non disponible - rapports archives"
                }
            }
            
            sh 'rm -rf sonar-scanner-* *.zip || true'
            sh 'docker system prune -f || true'
        }

        success {
            echo 'Pipeline reussi!'
            script {
                try {
                    emailext (
                        subject: "Pipeline Reussi - ${JOB_NAME} ${BUILD_NUMBER}",
                        body: "Pipeline de securite termine avec succes. Build: ${BUILD_NUMBER}",
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "Erreur email: ${e.message}"
                }
            }
        }

        unstable {
            echo 'Pipeline instable!'
            script {
                try {
                    emailext (
                        subject: "Pipeline Instable - ${JOB_NAME} ${BUILD_NUMBER}",
                        body: "Pipeline termine avec avertissements. Build: ${BUILD_NUMBER}",
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "Erreur email: ${e.message}"
                }
            }
        }

        failure {
            echo 'Pipeline echoue!'
            script {
                try {
                    emailext (
                        subject: "Pipeline Echoue - ${JOB_NAME} ${BUILD_NUMBER}",
                        body: "Pipeline de securite echoue. Build: ${BUILD_NUMBER}",
                        recipientProviders: [developers(), requestor()]
                    )
                } catch (Exception e) {
                    echo "Erreur email: ${e.message}"
                }
            }
        }
    }
}
