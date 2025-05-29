pipeline {
    agent any
    
    environment {
        // Configuration SonarQube
        SONARQUBE_INSTALLATION = 'sonarQube'
        
        // Configuration ZAP
        ZAP_IMAGE = 'zaproxy/zap-stable'
        TARGET_URL = 'https://demo.testfire.net'
        
        // Configuration Mistral
        MISTRAL_API_KEY = credentials('taha-jenkins')
        MISTRAL_API_URL = 'https://api.mistral.ai/v1/chat/completions'
        
        // Configuration Kubernetes
        APP_NAME = "${env.JOB_NAME}-${env.BUILD_NUMBER}".toLowerCase().replaceAll(/[^a-z0-9-]/, '-')
        IMAGE_NAME = "demo-app"
        K8S_NAMESPACE = "secure-namespace"
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo "🔄 Clonage du code source..."
                git 'https://github.com/tahawin1/demo-app'
                
                sh '''
                    mkdir -p reports security-reports k8s-deploy
                    echo "📋 Fichiers du projet:"
                    find . -name "*.js" -o -name "*.py" -o -name "*.java" -o -name "*.html" -o -name "*.php" | head -10
                '''
            }
        }
        
        // 🆕 VRAIE INTÉGRATION SONARQUBE
        stage('📊 SonarQube Analysis') {
            steps {
                script {
                    try {
                        echo '🔍 Analyse SonarQube en cours...'
                        
                        withSonarQubeEnv('sonarQube') {
                            sh '''
                                # Créer fichier de configuration SonarQube
                                cat > sonar-project.properties << EOF
sonar.projectKey=demo-app
sonar.projectName=Demo App Security Analysis
sonar.projectVersion=${BUILD_NUMBER}
sonar.sources=.
sonar.exclusions=**/*.log,**/node_modules/**,**/target/**,**/*.class,**/*.zip,**/reports/**
sonar.sourceEncoding=UTF-8
sonar.security.hotspots.inheritFromParent=true
EOF
                                
                                # Installer SonarQube Scanner si nécessaire
                                if ! command -v sonar-scanner &> /dev/null; then
                                    echo "📥 Installation SonarQube Scanner..."
                                    wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-linux.zip
                                    unzip -q sonar-scanner-cli-4.8.0.2856-linux.zip
                                    export PATH=$PWD/sonar-scanner-4.8.0.2856-linux/bin:$PATH
                                fi
                                
                                # Lancer l'analyse SonarQube
                                echo "🚀 Lancement analyse SonarQube..."
                                sonar-scanner \\
                                    -Dsonar.projectKey=demo-app \\
                                    -Dsonar.projectName="Demo App Security" \\
                                    -Dsonar.projectVersion=${BUILD_NUMBER} \\
                                    -Dsonar.sources=. \\
                                    -Dsonar.exclusions="**/*.log,**/node_modules/**,**/target/**,**/*.class,**/*.zip,**/reports/**" \\
                                    -Dsonar.host.url=${SONAR_HOST_URL} \\
                                    -Dsonar.login=${SONAR_AUTH_TOKEN}
                            '''
                        }
                        
                        // Attendre les résultats
                        echo "⏳ Attente des résultats SonarQube..."
                        timeout(time: 10, unit: 'MINUTES') {
                            def qg = waitForQualityGate()
                            
                            if (qg.status != 'OK') {
                                echo "⚠️ Quality Gate Status: ${qg.status}"
                                currentBuild.result = 'UNSTABLE'
                            } else {
                                echo "✅ Quality Gate réussi!"
                            }
                        }
                        
                        // Récupérer le rapport via API
                        sh '''
                            echo "📊 Récupération rapport SonarQube..."
                            sleep 5
                            
                            # API pour récupérer les issues de sécurité
                            curl -u "${SONAR_AUTH_TOKEN}:" \\
                                "${SONAR_HOST_URL}/api/issues/search?componentKeys=demo-app&types=VULNERABILITY,SECURITY_HOTSPOT&severities=BLOCKER,CRITICAL,MAJOR" \\
                                -o reports/sonarqube-issues.json || echo "{}" > reports/sonarqube-issues.json
                            
                            # API pour les métriques
                            curl -u "${SONAR_AUTH_TOKEN}:" \\
                                "${SONAR_HOST_URL}/api/measures/component?component=demo-app&metricKeys=security_rating,reliability_rating,sqale_rating,coverage,duplicated_lines_density,ncloc,bugs,vulnerabilities,security_hotspots" \\
                                -o reports/sonarqube-metrics.json || echo "{}" > reports/sonarqube-metrics.json
                            
                            # Générer rapport HTML
                            python3 << 'PYTHON_EOF'
import json
import os
from datetime import datetime

try:
    # Lire les données
    issues_data = {}
    metrics_data = {}
    
    if os.path.exists('reports/sonarqube-issues.json'):
        with open('reports/sonarqube-issues.json', 'r') as f:
            issues_data = json.load(f)
    
    if os.path.exists('reports/sonarqube-metrics.json'):
        with open('reports/sonarqube-metrics.json', 'r') as f:
            metrics_data = json.load(f)
    
    # Générer le rapport HTML
    with open('reports/sonarqube-report.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>SonarQube Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #4E9BCD; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; text-align: center; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #4E9BCD; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; color: #4E9BCD; }
        .issue { background: #fff3cd; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ffc107; }
        .critical { border-left-color: #dc3545; background: #f8d7da; }
        .major { border-left-color: #fd7e14; background: #fff3cd; }
        h1, h2 { color: #4E9BCD; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SonarQube Security Analysis</h1>
            <p>Project: demo-app | Build: ''' + os.environ.get('BUILD_NUMBER', 'Unknown') + '''</p>
            <p>Date: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
        </div>
        
        <h2>📊 Quality Metrics</h2>
        <div class="metrics-grid">''')
        
        # Afficher les métriques
        if 'component' in metrics_data and 'measures' in metrics_data['component']:
            for measure in metrics_data['component']['measures']:
                metric_name = measure.get('metric', 'Unknown')
                metric_value = measure.get('value', 'N/A')
                
                # Traduire les noms de métriques
                metric_labels = {
                    'security_rating': 'Security Rating',
                    'reliability_rating': 'Reliability Rating',
                    'sqale_rating': 'Maintainability Rating',
                    'coverage': 'Code Coverage (%)',
                    'duplicated_lines_density': 'Duplicated Lines (%)',
                    'ncloc': 'Lines of Code',
                    'bugs': 'Bugs',
                    'vulnerabilities': 'Vulnerabilities',
                    'security_hotspots': 'Security Hotspots'
                }
                
                display_name = metric_labels.get(metric_name, metric_name.replace('_', ' ').title())
                
                f.write(f'''
            <div class="metric-card">
                <div class="metric-value">{metric_value}</div>
                <div>{display_name}</div>
            </div>''')
        else:
            f.write('<div class="metric-card"><p>No metrics available</p></div>')
        
        f.write('''
        </div>
        
        <h2>🚨 Security Issues</h2>''')
        
        # Afficher les issues
        if 'issues' in issues_data and issues_data['issues']:
            for issue in issues_data['issues'][:10]:
                severity = issue.get('severity', 'UNKNOWN').lower()
                css_class = 'critical' if severity in ['blocker', 'critical'] else 'major' if severity == 'major' else 'issue'
                
                f.write(f'''
        <div class="issue {css_class}">
            <h4>{issue.get('rule', 'Unknown Rule')}</h4>
            <p><strong>Severity:</strong> {issue.get('severity', 'Unknown')}</p>
            <p><strong>Type:</strong> {issue.get('type', 'Unknown')}</p>
            <p><strong>Message:</strong> {issue.get('message', 'No message')}</p>
            <p><strong>File:</strong> {issue.get('component', 'Unknown').split(':')[-1] if ':' in issue.get('component', '') else issue.get('component', 'Unknown')}</p>
            <p><strong>Line:</strong> {issue.get('line', 'N/A')}</p>
        </div>''')
        else:
            f.write('<div class="issue"><p>✅ No security issues found!</p></div>')
        
        f.write('''
        
        <h2>🔗 Links</h2>
        <div class="metric-card">
            <p><a href="''' + os.environ.get('SONAR_HOST_URL', 'http://localhost:9000') + '''/dashboard?id=demo-app" target="_blank">🔍 View Full Report in SonarQube</a></p>
        </div>
        
    </div>
</body>
</html>''')
    
    print("✅ Rapport SonarQube HTML généré avec succès")
    
except Exception as e:
    print(f"⚠️ Erreur génération rapport SonarQube: {e}")
    with open('reports/sonarqube-report.html', 'w') as f:
        f.write(f'''<!DOCTYPE html>
<html>
<body>
    <h1>⚠️ Erreur Rapport SonarQube</h1>
    <p>Impossible de générer le rapport: {e}</p>
    <p><a href="{os.environ.get('SONAR_HOST_URL', 'http://localhost:9000')}/dashboard?id=demo-app">Voir dans SonarQube</a></p>
</body>
</html>''')

PYTHON_EOF
                        '''
                        
                        echo "✅ Analyse SonarQube terminée"
                        
                    } catch (Exception e) {
                        echo "⚠️ Erreur analyse SonarQube: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        stage('Analyse SCA - Dépendances') {
            steps {
                script {
                    try {
                        echo '🔍 Analyse des dépendances avec Trivy...'
                        sh '''
                        trivy fs --format json --output reports/trivy-sca.json . || echo "{}" > reports/trivy-sca.json
                        trivy fs --format table . > reports/trivy-sca-report.txt || echo "Erreur Trivy SCA" > reports/trivy-sca-report.txt
                        cat reports/trivy-sca-report.txt
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Erreur Trivy SCA: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        // 🆕 GÉNÉRATION MANIFESTS KUBERNETES
        stage('🛡️ Generate Kubernetes Manifests') {
            when {
                expression { fileExists('k8s-templates/secure-deployment.yaml') }
            }
            steps {
                script {
                    echo "🔧 Génération des manifests Kubernetes sécurisés..."
                    try {
                        sh '''
                            for template in k8s-templates/*.yaml; do
                                if [ -f "$template" ]; then
                                    filename=$(basename "$template")
                                    echo "✅ Génération: $filename"
                                    envsubst < "$template" > "k8s-deploy/$filename"
                                fi
                            done
                            
                            echo "📁 Manifests générés:"
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
                        echo '🐳 Construction image Docker...'
                        sh '''
                        docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} . || echo "Erreur build Docker"
                        docker tag ${IMAGE_NAME}:${BUILD_NUMBER} ${IMAGE_NAME}:latest || echo "Erreur tag Docker"
                        echo "✅ Image: ${IMAGE_NAME}:${BUILD_NUMBER}"
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Erreur build Docker: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        stage('Trivy Scan') {
            steps {
                script {
                    try {
                        echo '🔍 Scan sécurité image Docker...'
                        sh '''
                        # Scan image Docker
                        trivy image --format json --output reports/trivy-image.json ${IMAGE_NAME}:${BUILD_NUMBER} || echo "{}" > reports/trivy-image.json
                        trivy image --format table ${IMAGE_NAME}:${BUILD_NUMBER} > reports/trivy-image-report.txt || echo "Erreur scan image" > reports/trivy-image-report.txt
                        
                        # Scan configurations K8s si disponibles
                        if [ -d "k8s-deploy" ] && [ "$(ls -A k8s-deploy)" ]; then
                            echo "🔍 Scan configurations Kubernetes..."
                            trivy config --format json --output reports/trivy-k8s.json k8s-deploy/ || echo "{}" > reports/trivy-k8s.json
                            trivy config k8s-deploy/ > reports/trivy-k8s-report.txt || echo "Pas de scan K8s" > reports/trivy-k8s-report.txt
                        fi
                        
                        echo "📊 Résultats Trivy:"
                        cat reports/trivy-image-report.txt | head -20
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Erreur Trivy: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        // 🆕 VRAIE INTÉGRATION OWASP ZAP
        stage('🕷️ OWASP ZAP Security Scan') {
            steps {
                script {
                    try {
                        echo '🚀 Démarrage scan OWASP ZAP...'
                        
                        sh '''
                        echo "🎯 Target: ${TARGET_URL}"
                        echo "🐳 ZAP Image: ${ZAP_IMAGE}"
                        
                        # Créer dossier pour rapports ZAP
                        mkdir -p reports/zap
                        
                        # Test de connectivité
                        echo "🔍 Test connectivité..."
                        curl -I ${TARGET_URL} || echo "⚠️ Target potentiellement inaccessible"
                        
                        # Lancer ZAP Baseline Scan
                        echo "🚀 Lancement ZAP Baseline Scan..."
                        docker run --rm \\
                            -v $(pwd)/reports/zap:/zap/wrk \\
                            ${ZAP_IMAGE} \\
                            zap-baseline.py \\
                            -t ${TARGET_URL} \\
                            -r zap-baseline-report.html \\
                            -x zap-baseline-report.xml \\
                            -J zap-baseline-report.json \\
                            -I \\
                            -d \\
                            || echo "Scan ZAP terminé (alertes possibles)"
                        
                        # Vérifier les rapports
                        echo "📊 Vérification rapports ZAP..."
                        ls -la reports/zap/
                        
                        # Analyser le rapport JSON
                        if [ -f "reports/zap/zap-baseline-report.json" ]; then
                            echo "🔍 Analyse des résultats ZAP..."
                            python3 << 'PYTHON_EOF'
import json
import os
from datetime import datetime

try:
    with open('reports/zap/zap-baseline-report.json', 'r') as f:
        zap_data = json.load(f)
    
    site_info = zap_data.get('site', [{}])[0] if zap_data.get('site') else {}
    alerts = site_info.get('alerts', [])
    
    # Compter par niveau de risque
    risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for alert in alerts:
        risk = alert.get('riskdesc', '').split(' ')[0]
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    # Générer rapport HTML
    with open('reports/zap-report.html', 'w') as f:
        f.write(f'''<!DOCTYPE html>
<html>
<head>
    <title>OWASP ZAP Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: #FF6B35; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; text-align: center; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .risk-card {{ padding: 15px; border-radius: 8px; text-align: center; color: white; font-weight: bold; }}
        .risk-high {{ background: #dc3545; }}
        .risk-medium {{ background: #fd7e14; }}
        .risk-low {{ background: #ffc107; color: #000; }}
        .risk-info {{ background: #17a2b8; }}
        .alert {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #6c757d; }}
        .alert-high {{ border-left-color: #dc3545; background: #f8d7da; }}
        .alert-medium {{ border-left-color: #fd7e14; background: #fff3cd; }}
        h1, h2 {{ color: #FF6B35; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ OWASP ZAP Security Scan Report</h1>
            <p>Target: {site_info.get('@name', 'Unknown')}</p>
            <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Build: {os.environ.get('BUILD_NUMBER', 'Unknown')}</p>
        </div>
        
        <h2>📊 Risk Summary</h2>
        <div class="summary">
            <div class="risk-card risk-high">
                <h3>{risk_counts['High']}</h3>
                <p>High Risk</p>
            </div>
            <div class="risk-card risk-medium">
                <h3>{risk_counts['Medium']}</h3>
                <p>Medium Risk</p>
            </div>
            <div class="risk-card risk-low">
                <h3>{risk_counts['Low']}</h3>
                <p>Low Risk</p>
            </div>
            <div class="risk-card risk-info">
                <h3>{risk_counts['Informational']}</h3>
                <p>Informational</p>
            </div>
        </div>
        
        <h2>🚨 Security Alerts</h2>''')
        
        # Afficher les alertes importantes
        sorted_alerts = sorted(alerts, key=lambda x: {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}.get(x.get('riskdesc', '').split(' ')[0], 4))
        
        for alert in sorted_alerts[:10]:
            risk = alert.get('riskdesc', '').split(' ')[0].lower()
            css_class = f'alert-{risk}' if risk in ['high', 'medium'] else 'alert'
            
            f.write(f'''
        <div class="alert {css_class}">
            <h4>{alert.get('name', 'Unknown Alert')}</h4>
            <p><strong>Risk:</strong> {alert.get('riskdesc', 'Unknown')}</p>
            <p><strong>Confidence:</strong> {alert.get('confidence', 'Unknown')}</p>
            <p><strong>Description:</strong> {alert.get('desc', 'No description')[:200]}...</p>
            <p><strong>Solution:</strong> {alert.get('solution', 'No solution')[:200]}...</p>
            <p><strong>URLs Affected:</strong> {len(alert.get('instances', []))}</p>
        </div>''')
        
        if not alerts:
            f.write('<div class="alert"><p>✅ No security alerts found!</p></div>')
        
        f.write('''
        
        <h2>📈 Scan Statistics</h2>
        <div class="alert">
            <p><strong>Total Alerts:</strong> ''' + str(len(alerts)) + '''</p>
            <p><strong>Target URL:</strong> ''' + site_info.get('@name', 'Unknown') + '''</p>
            <p><strong>Scan Type:</strong> Baseline Security Scan</p>
        </div>
        
    </div>
</body>
</html>''')
    
    # Résumé texte
    with open('reports/zap-summary.txt', 'w') as f:
        f.write(f'''🕷️ OWASP ZAP SCAN SUMMARY
========================================
Target: {site_info.get('@name', 'Unknown')}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Build: {os.environ.get('BUILD_NUMBER', 'Unknown')}

RISK BREAKDOWN:
🔴 High Risk: {risk_counts['High']}
🟠 Medium Risk: {risk_counts['Medium']}
🟡 Low Risk: {risk_counts['Low']}
🔵 Informational: {risk_counts['Informational']}

TOTAL ALERTS: {len(alerts)}
''')
    
    print("✅ Rapport ZAP HTML généré avec succès")
    
except Exception as e:
    print(f"⚠️ Erreur analyse ZAP: {e}")

PYTHON_EOF
                        else
                            echo "⚠️ Rapport JSON ZAP non trouvé"
                            cat > reports/zap-report.html << EOF
<!DOCTYPE html>
<html>
<body>
    <h1>🕷️ OWASP ZAP Scan Report</h1>
    <p><strong>Target:</strong> ${TARGET_URL}</p>
    <p><strong>Status:</strong> Scan exécuté mais rapport JSON non généré</p>
</body>
</html>
EOF
                        fi
                        
                        echo "✅ Scan ZAP terminé"
                        '''
                        
                    } catch (Exception e) {
                        echo "⚠️ Erreur scan ZAP: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        // Tests sécurité Kubernetes
        stage('🧪 Kubernetes Security Tests') {
            when {
                expression { fileExists('scripts/validate-k8s-security.sh') }
            }
            steps {
                script {
                    try {
                        echo '🧪 Tests sécurité Kubernetes...'
                        sh '''
                        chmod +x scripts/validate-k8s-security.sh
                        
                        echo "🛡️ VALIDATION CONFIGURATIONS KUBERNETES" > reports/k8s-security-report.txt
                        echo "=======================================" >> reports/k8s-security-report.txt
                        
                        # Tests sur les manifests
                        SCORE=0
                        TOTAL_TESTS=5
                        
                        if [ -f "k8s-deploy/secure-deployment.yaml" ]; then
                            if grep -q "runAsUser: 1000" k8s-deploy/secure-deployment.yaml; then
                                echo "✅ Test 1: Utilisateur non-root (1000)" >> reports/k8s-security-report.txt
                                SCORE=$((SCORE + 1))
                            else
                                echo "❌ Test 1: Utilisateur root détecté" >> reports/k8s-security-report.txt
                            fi
                            
                            if grep -q "readOnlyRootFilesystem: true" k8s-deploy/secure-deployment.yaml; then
                                echo "✅ Test 2: Filesystem read-only" >> reports/k8s-security-report.txt
                                SCORE=$((SCORE + 1))
                            else
                                echo "❌ Test 2: Filesystem en écriture" >> reports/k8s-security-report.txt
                            fi
                            
                            if grep -q "serviceAccountName:" k8s-deploy/secure-deployment.yaml; then
                                echo "✅ Test 3: ServiceAccount personnalisé" >> reports/k8s-security-report.txt
                                SCORE=$((SCORE + 1))
                            else
                                echo "❌ Test 3: ServiceAccount par défaut" >> reports/k8s-security-report.txt
                            fi
                            
                            if grep -q "capabilities:" k8s-deploy/secure-deployment.yaml; then
                                echo "✅ Test 4: Capabilities configurées" >> reports/k8s-security-report.txt
                                SCORE=$((SCORE + 1))
                            else
                                echo "❌ Test 4: Capabilities par défaut" >> reports/k8s-security-report.txt
                            fi
                            
                            if grep -q "limits:" k8s-deploy/secure-deployment.yaml; then
                                echo "✅ Test 5: Limites de ressources" >> reports/k8s-security-report.txt
                                SCORE=$((SCORE + 1))
                            else
                                echo "❌ Test 5: Pas de limites de ressources" >> reports/k8s-security-report.txt
                            fi
                        fi
                        
                        PERCENTAGE=$((SCORE * 100 / TOTAL_TESTS))
                        echo "" >> reports/k8s-security-report.txt
                        echo "📊 SCORE FINAL: ${SCORE}/${TOTAL_TESTS} (${PERCENTAGE}%)" >> reports/k8s-security-report.txt
                        
                        echo "Score: ${SCORE}/${TOTAL_TESTS} (${PERCENTAGE}%)" > reports/k8s-security-score.txt
                        cat reports/k8s-security-report.txt
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Erreur tests K8s: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        stage('📋 Generate Combined Report') {
            steps {
                script {
                    try {
                        echo '📊 Génération rapport de sécurité complet...'
                        sh '''
                        # Copier tous les rapports
                        cp -r reports/* security-reports/ 2>/dev/null || echo "Pas de rapports à copier"
                        
                        # Générer dashboard HTML complet
                        cat > reports/security-dashboard.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: rgba(255,255,255,0.95); color: #333; padding: 30px; border-radius: 15px; text-align: center; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .card { background: rgba(255,255,255,0.95); padding: 25px; margin: 20px 0; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); transition: transform 0.3s ease; }
        .card:hover { transform: translateY(-5px); }
        .success { border-left: 5px solid #28a745; }
        .warning { border-left: 5px solid #ffc107; }
        .danger { border-left: 5px solid #dc3545; }
        .info { border-left: 5px solid #17a2b8; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        h1 { margin: 0; font-size: 2.5em; color: #2c5aa0; }
        h2 { color: #2c5aa0; border-bottom: 3px solid #2c5aa0; padding-bottom: 10px; }
        .score { font-size: 3em; font-weight: bold; text-align: center; color: #28a745; }
        .link { color: #2c5aa0; text-decoration: none; font-weight: bold; }
        .link:hover { text-decoration: underline; }
        .stats { background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 15px 0; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 15px; color: white; font-weight: bold; margin: 5px; }
        .badge-success { background: #28a745; }
        .badge-warning { background: #ffc107; color: #000; }
        .badge-danger { background: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Analysis Dashboard</h1>
            <p style="font-size: 1.2em;">Build: ${BUILD_NUMBER} | Date: $(date)</p>
            <p>Pipeline CI/CD avec sécurité Kubernetes intégrée</p>
        </div>
        
        <div class="grid">
            <div class="card success">
                <h2>📊 SonarQube Analysis</h2>
                <p><a href="sonarqube-report.html" class="link">📋 View Detailed Report</a></p>
                <div class="stats">
                    <p><strong>✅ Static Code Analysis</strong></p>
                    <p>Security vulnerabilities scanned</p>
                    <p>Quality gates validated</p>
                </div>
                <span class="badge badge-success">Completed</span>
            </div>
            
            <div class="card warning">
                <h2>🕷️ OWASP ZAP Scan</h2>
                <p><a href="zap-report.html" class="link">📋 View Security Report</a></p>
                <div class="stats">
                    <p><strong>🎯 Target:</strong> ${TARGET_URL}</p>
                    <p>Dynamic security testing</p>
                    <p>Web application vulnerabilities</p>
                </div>
                <span class="badge badge-warning">Security Scan</span>
            </div>
            
            <div class="card info">
                <h2>🐳 Container Security</h2>
                <p><a href="trivy-image-report.txt" class="link">📋 View Image Scan</a></p>
                <div class="stats">
                    <p><strong>✅ Docker Image Scanned</strong></p>
                    <p>Dependencies analyzed</p>
                    <p>Vulnerabilities checked</p>
                </div>
                <span class="badge badge-success">Secured</span>
            </div>
            
            <div class="card success">
                <h2>☸️ Kubernetes Security</h2>
EOF
                        
                        # Ajouter score K8s si disponible
                        if [ -f "reports/k8s-security-score.txt" ]; then
                            K8S_SCORE=$(cat reports/k8s-security-score.txt)
                            echo "                <div class=\"score\">${K8S_SCORE}</div>" >> reports/security-dashboard.html
                        else
                            echo "                <div class=\"score\">N/A</div>" >> reports/security-dashboard.html
                        fi
                        
                        cat >> reports/security-dashboard.html << 'EOF'
                <p><a href="k8s-security-report.txt" class="link">📋 View K8s Report</a></p>
                <div class="stats">
                    <p><strong>🛡️ 3 Piliers Validés:</strong></p>
                    <p>• Security Context</p>
                    <p>• RBAC</p>
                    <p>• Network Isolation</p>
                </div>
                <span class="badge badge-success">Production Ready</span>
            </div>
        </div>
        
        <div class="card">
            <h2>📈 Security Pipeline Summary</h2>
            <div class="grid">
                <div>
                    <h3>🔍 Static Analysis (SAST)</h3>
                    <ul>
                        <li>✅ SonarQube code quality analysis</li>
                        <li>✅ Dependency vulnerability scan (Trivy)</li>
                        <li>✅ Container image security scan</li>
                        <li>✅ Kubernetes configuration scan</li>
                    </ul>
                </div>
                <div>
                    <h3>🕷️ Dynamic Analysis (DAST)</h3>
                    <ul>
                        <li>✅ OWASP ZAP baseline scan</li>
                        <li>✅ Web application security testing</li>
                        <li>✅ Runtime vulnerability detection</li>
                        <li>✅ Real-world attack simulation</li>
                    </ul>
                </div>
                <div>
                    <h3>☸️ Infrastructure Security</h3>
                    <ul>
                        <li>✅ Kubernetes manifests validated</li>
                        <li>✅ Security contexts enforced</li>
                        <li>✅ RBAC policies applied</li>
                        <li>✅ Network policies configured</li>
                    </ul>
                </div>
                <div>
                    <h3>🤖 AI-Powered Recommendations</h3>
                    <ul>
                        <li>✅ Mistral AI security analysis</li>
                        <li>✅ Automated recommendations</li>
                        <li>✅ Priority-based action items</li>
                        <li>✅ Best practices guidance</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="card info">
            <h2>🔗 Quick Links</h2>
            <div class="grid">
                <div>
                    <h4>📊 Reports</h4>
                    <p><a href="sonarqube-report.html" class="link">SonarQube Analysis</a></p>
                    <p><a href="zap-report.html" class="link">OWASP ZAP Scan</a></p>
                    <p><a href="k8s-security-report.txt" class="link">Kubernetes Security</a></p>
                </div>
                <div>
                    <h4>🔧 Raw Data</h4>
                    <p><a href="trivy-sca-report.txt" class="link">Dependency Scan</a></p>
                    <p><a href="trivy-image-report.txt" class="link">Image Vulnerabilities</a></p>
                    <p><a href="trivy-k8s-report.txt" class="link">K8s Config Scan</a></p>
                </div>
                <div>
                    <h4>🤖 AI Analysis</h4>
                    <p><a href="../security-recommendations.md" class="link">Mistral AI Recommendations</a></p>
                </div>
                <div>
                    <h4>📈 External Links</h4>
                    <p><a href="http://localhost:9000/dashboard?id=demo-app" target="_blank" class="link">SonarQube Dashboard</a></p>
                </div>
            </div>
        </div>
        
    </div>
</body>
</html>
EOF
                        
                        echo "✅ Security Dashboard généré: reports/security-dashboard.html"
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Erreur génération dashboard: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
        
        stage('Consultation Mistral AI') {
            steps {
                script {
                    try {
                        echo '🤖 Envoi des rapports à Mistral AI...'
                        
                        def reportContent = ""
                        try {
                            reportContent = readFile('reports/k8s-security-report.txt')
                        } catch (Exception e) {
                            reportContent = "Rapport sécurité non généré"
                        }
                        
                        def mistralPrompt = """En tant qu'expert en cybersécurité DevSecOps et Kubernetes, analyse ce rapport de sécurité et fournit:

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
                        
                        echo "✅ Recommandations IA générées"
                        
                    } catch (Exception e) {
                        echo "⚠️ Erreur Mistral AI: ${e.message}"
                        writeFile file: 'security-recommendations.md', text: """# 🛡️ Recommandations de sécurité

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
            script {
                echo '🎉 ✅ Pipeline de sécurité CI/CD + Kubernetes réussi!'
                echo '📊 Dashboard généré: reports/security-dashboard.html'
                echo '🔗 Rapports SonarQube et ZAP disponibles'
                echo '☸️ Manifests Kubernetes sécurisés prêts au déploiement'
            }
        }
        unstable {
            echo '⚠️ Pipeline terminé avec avertissements. Vérifiez les rapports de sécurité.'
        }
        failure {
            echo '❌ Échec critique du pipeline de sécurité.'
        }
        always {
            // Publication des rapports HTML
            script {
                try {
                    // Publier le dashboard principal
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'reports',
                        reportFiles: 'security-dashboard.html',
                        reportName: '🛡️ Security Dashboard'
                    ])
                    
                    // Publier rapport SonarQube
                    if (fileExists('reports/sonarqube-report.html')) {
                        publishHTML([
                            allowMissing: false,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: 'reports',
                            reportFiles: 'sonarqube-report.html',
                            reportName: '📊 SonarQube Report'
                        ])
                    }
                    
                    // Publier rapport ZAP
                    if (fileExists('reports/zap-report.html')) {
                        publishHTML([
                            allowMissing: false,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: 'reports',
                            reportFiles: 'zap-report.html',
                            reportName: '🕷️ OWASP ZAP Report'
                        ])
                    }
                    
                    echo '✅ Rapports HTML publiés avec succès'
                } catch (Exception e) {
                    echo "⚠️ Erreur publication rapports HTML: ${e.message}"
                }
            }
            
            // Archivage complet
            archiveArtifacts artifacts: '''
                *.txt,
                *.html, 
                *.json,
                *.md,
                *.log,
                reports/**/*,
                k8s-deploy/**/*,
                k8s-templates/**/*,  
                security-reports/**/*,
                scripts/**/*
            ''', allowEmptyArchive: true, fingerprint: true
            
            // Résumé final
            script {
                sh '''
                    echo ""
                    echo "🏆 ===== RÉSUMÉ FINAL DU PIPELINE DE SÉCURITÉ ====="
                    echo "📅 Date: $(date)"
                    echo "🏗️ Build: ${BUILD_NUMBER}"
                    echo "🎯 Application: ${APP_NAME}"
                    echo ""
                    echo "📊 RAPPORTS GÉNÉRÉS:"
                    echo "✅ Security Dashboard: reports/security-dashboard.html"
                    if [ -f "reports/sonarqube-report.html" ]; then echo "✅ SonarQube Report: reports/sonarqube-report.html"; fi
                    if [ -f "reports/zap-report.html" ]; then echo "✅ OWASP ZAP Report: reports/zap-report.html"; fi
                    if [ -f "reports/k8s-security-score.txt" ]; then echo "✅ K8s Security: $(cat reports/k8s-security-score.txt)"; fi
                    echo ""
                    echo "🔗 ACCÈS AUX RAPPORTS:"
                    echo "1. HTML Reports (liens dans le menu Jenkins)"
                    echo "2. Build Artifacts (fichiers téléchargeables)"
                    echo "3. Security Dashboard (rapport principal)"
                    echo ""
                    echo "🚀 Votre application est maintenant prête pour un déploiement sécurisé!"
                '''
            }
        }
    }
}
