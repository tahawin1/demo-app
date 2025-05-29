pipeline {
    agent any
    environment {
        // Configuration SonarQube corrigée pour votre setup
        SONARQUBE_INSTALLATION = 'sonarQube' // Correspond à votre configuration Jenkins
        
        // Autres configurations existantes
        ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        TARGET_URL = 'http://demo.testfire.net'
        MISTRAL_API_KEY = credentials('taha-jenkins')
        MISTRAL_API_URL = 'https://api.mistral.ai/v1/chat/completions'
        
        // Configurations Kubernetes
        APP_NAME = "${env.JOB_NAME}-${env.BUILD_NUMBER}".toLowerCase().replaceAll(/[^a-z0-9-]/, '-')
        IMAGE_NAME = "demo-app"
        K8S_NAMESPACE = "secure-namespace"
        DOCKER_REGISTRY = "localhost:5000"
        KUBECONFIG = credentials('kubeconfig')
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo "🔄 Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app'
                
                sh '''
                    mkdir -p k8s-templates
                    mkdir -p k8s-deploy
                    mkdir -p security-reports
                    mkdir -p scripts
                '''
            }
        }
        
        stage('Analyse SonarQube') {
            steps {
                script {
                    try {
                        echo "🚀 Début de l'analyse SonarQube..."
                        
                        // Créer le fichier sonar-project.properties
                        writeFile file: 'sonar-project.properties', text: '''# Configuration SonarQube pour demo-app
sonar.projectKey=demo-app
sonar.projectName=Demo App Security Pipeline
sonar.sources=.
sonar.exclusions=**/node_modules/**,**/target/**,**/*.log,**/k8s-templates/**,**/k8s-deploy/**,**/security-reports/**,**/scripts/**
sonar.sourceEncoding=UTF-8

# Configuration pour différents langages
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.java.source=11
sonar.python.coverage.reportPaths=coverage.xml

# Règles de qualité
sonar.qualitygate.wait=false
'''
                        
                        // Utilisation de votre configuration SonarQube
                        withSonarQubeEnv('sonarQube') {
                            sh '''
                                echo "🔍 Configuration SonarQube:"
                                echo "URL: ${SONAR_HOST_URL}"
                                echo "Projet: demo-app"
                                
                                # Test de connectivité
                                echo "📡 Test de connectivité..."
                                HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${SONAR_HOST_URL}/api/system/status")
                                echo "Code de réponse SonarQube: ${HTTP_CODE}"
                                
                                # Installation et exécution de SonarScanner
                                if ! command -v sonar-scanner >/dev/null 2>&1; then
                                    echo "📥 Installation de SonarScanner..."
                                    wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-linux.zip
                                    unzip -q sonar-scanner-cli-4.8.0.2856-linux.zip
                                    SCANNER_CMD="./sonar-scanner-4.8.0.2856-linux/bin/sonar-scanner"
                                else
                                    echo "✅ SonarScanner déjà installé"
                                    SCANNER_CMD="sonar-scanner"
                                fi
                                
                                echo "🚀 Lancement de l'analyse..."
                                ${SCANNER_CMD} \\
                                    -Dsonar.projectKey=demo-app \\
                                    -Dsonar.projectName="Demo App Security Pipeline" \\
                                    -Dsonar.sources=. \\
                                    -Dsonar.exclusions="**/node_modules/**,**/target/**,**/*.log,**/k8s-templates/**,**/security-reports/**" \\
                                    -Dsonar.host.url="${SONAR_HOST_URL}" \\
                                    -Dsonar.login="${SONAR_AUTH_TOKEN}"
                            '''
                        }
                        
                        echo "✅ Analyse SonarQube terminée avec succès!"
                        
                    } catch (Exception e) {
                        echo "❌ Erreur lors de l'analyse SonarQube: ${e.message}"
                        echo "🔧 Vérifications de diagnostic:"
                        
                        sh '''
                            echo "1. État du serveur SonarQube:"
                            curl -s http://localhost:9000/api/system/status || echo "❌ SonarQube inaccessible"
                            
                            echo "2. Contenu du répertoire:"
                            ls -la
                            
                            echo "3. Fichier de configuration SonarQube:"
                            if [ -f "sonar-project.properties" ]; then
                                cat sonar-project.properties
                            else
                                echo "❌ Fichier sonar-project.properties manquant"
                            fi
                        '''
                        
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        stage('Quality Gate SonarQube') {
            steps {
                script {
                    try {
                        echo "⏳ Vérification du Quality Gate..."
                        timeout(time: 3, unit: 'MINUTES') {
                            def qg = waitForQualityGate()
                            if (qg.status != 'OK') {
                                echo "⚠️ Quality Gate: ${qg.status}"
                                echo "📊 Détails: ${qg}"
                                currentBuild.result = 'UNSTABLE'
                            } else {
                                echo "✅ Quality Gate réussi!"
                            }
                        }
                    } catch (Exception e) {
                        echo "ℹ️ Quality Gate non disponible ou timeout: ${e.message}"
                        // Ne pas faire échouer le pipeline
                    }
                }
            }
        }
        
        stage('Analyse SCA - Dépendances') {
            steps {
                script {
                    try {
                        echo '🔍 Analyse des dépendances (SCA) avec Trivy...'
                        sh '''
                        if command -v trivy >/dev/null 2>&1; then
                            trivy fs --scanners vuln,license . > trivy-sca-report.txt
                        else
                            echo "❌ Trivy non installé, simulation du rapport..." > trivy-sca-report.txt
                        fi
                        cat trivy-sca-report.txt
                        '''
                    } catch (Exception e) {
                        echo "❌ Erreur lors de l'analyse SCA: ${e.message}"
                        sh 'echo "Erreur lors du scan SCA" > trivy-sca-report.txt'
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        // Continuez avec le reste de vos stages...
        // [Ajoutez ici tous vos autres stages du pipeline original]
    }
    
    post {
        always {
            echo '🧹 Nettoyage et archivage...'
            
            // Archive des rapports
            archiveArtifacts artifacts: '**/*-report.txt, **/*-report.html, security-reports/*', allowEmptyArchive: true
            
            // Nettoyage des fichiers temporaires
            sh '''
                rm -rf sonar-scanner-*
                rm -f *.zip
            '''
        }
        
        success {
            echo '✅ Pipeline terminé avec succès!'
        }
        
        unstable {
            echo '⚠️ Pipeline terminé avec des avertissements!'
        }
        
        failure {
            echo '❌ Pipeline échoué!'
        }
    }
}
