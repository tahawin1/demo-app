pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = 'your-registry.com'
        DOCKER_CREDENTIALS = 'docker-hub-credentials'
        SONARQUBE_SERVER = 'SonarQube'
        KUBECONFIG_CREDENTIALS = 'kubeconfig-credentials'
        NAMESPACE = 'production'
        APP_NAME = 'tahtech-app'
        TRIVY_SEVERITY = 'CRITICAL,HIGH'
        SNYK_TOKEN = credentials('snyk-token')
    }
    
    stages {
        stage('Checkout SCM') {
            steps {
                checkout scm
                echo "Code source récupéré depuis ${env.GIT_BRANCH}"
            }
        }
        
        stage('Analyse SonarQube') {
            steps {
                withSonarQubeEnv(SONARQUBE_SERVER) {
                    sh '''
                        sonar-scanner \
                          -Dsonar.projectKey=${APP_NAME} \
                          -Dsonar.sources=. \
                          -Dsonar.host.url=$SONAR_HOST_URL \
                          -Dsonar.login=$SONAR_AUTH_TOKEN
                    '''
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 1, unit: 'HOURS') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    docker.build("${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER}")
                    docker.build("${DOCKER_REGISTRY}/${APP_NAME}:latest")
                }
            }
        }
        
        stage('Scan des vulnérabilités - Trivy') {
            steps {
                script {
                    // Scan avec Trivy
                    sh """
                        trivy image --severity ${TRIVY_SEVERITY} \
                          --no-progress \
                          --exit-code 1 \
                          --format json \
                          --output trivy-report.json \
                          ${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER}
                    """
                    
                    // Archiver le rapport
                    archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('Scan des dépendances - Snyk') {
            steps {
                script {
                    sh """
                        snyk container test ${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER} \
                          --severity-threshold=high \
                          --json > snyk-report.json || true
                    """
                    
                    // Vérifier les vulnérabilités critiques
                    def snykReport = readJSON file: 'snyk-report.json'
                    if (snykReport.vulnerabilities?.any { it.severity == 'critical' }) {
                        error "Vulnérabilités critiques détectées par Snyk!"
                    }
                    
                    archiveArtifacts artifacts: 'snyk-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('Scan OWASP ZAP') {
            when {
                expression { params.RUN_ZAP_SCAN == true }
            }
            steps {
                script {
                    // Démarrer l'application temporairement pour le scan
                    sh "docker run -d --name ${APP_NAME}-test -p 8090:8080 ${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER}"
                    
                    // Attendre que l'application démarre
                    sleep(time: 30, unit: 'SECONDS')
                    
                    // Lancer le scan ZAP
                    sh """
                        docker run --rm -v \$(pwd):/zap/wrk/:rw \
                          -t owasp/zap2docker-stable zap-baseline.py \
                          -t http://host.docker.internal:8090 \
                          -r zap-report.html \
                          -x zap-report.xml
                    """
                    
                    // Arrêter le conteneur de test
                    sh "docker stop ${APP_NAME}-test && docker rm ${APP_NAME}-test"
                    
                    archiveArtifacts artifacts: 'zap-report.*', allowEmptyArchive: true
                }
            }
        }
        
        stage('Push Docker Image') {
            when {
                allOf {
                    expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
                    branch 'main'
                }
            }
            steps {
                script {
                    docker.withRegistry("https://${DOCKER_REGISTRY}", DOCKER_CREDENTIALS) {
                        docker.image("${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER}").push()
                        docker.image("${DOCKER_REGISTRY}/${APP_NAME}:latest").push()
                    }
                }
            }
        }
        
        stage('Vérification Image ZAP') {
            steps {
                script {
                    // Créer un manifeste de déploiement temporaire
                    writeFile file: 'temp-deployment.yaml', text: """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${APP_NAME}-security-check
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${APP_NAME}-security-check
  template:
    metadata:
      labels:
        app: ${APP_NAME}-security-check
    spec:
      containers:
      - name: ${APP_NAME}
        image: ${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER}
        ports:
        - containerPort: 8080
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
"""
                    
                    // Vérifier la conformité avec les politiques de sécurité Kubernetes
                    sh """
                        kubectl auth can-i create deployments --namespace=${NAMESPACE}
                        kubectl apply --dry-run=client -f temp-deployment.yaml
                    """
                }
            }
        }
        
        stage('Déploiement sur Kubernetes') {
            when {
                allOf {
                    expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
                    branch 'main'
                }
            }
            steps {
                script {
                    withCredentials([file(credentialsId: KUBECONFIG_CREDENTIALS, variable: 'KUBECONFIG')]) {
                        // Créer le namespace s'il n'existe pas
                        sh "kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -"
                        
                        // Appliquer les manifestes Kubernetes
                        sh """
                            # Mettre à jour l'image dans le déploiement
                            kubectl set image deployment/${APP_NAME} \
                              ${APP_NAME}=${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER} \
                              -n ${NAMESPACE} \
                              --record=true
                            
                            # Vérifier le statut du déploiement
                            kubectl rollout status deployment/${APP_NAME} -n ${NAMESPACE} --timeout=5m
                            
                            # Afficher les pods déployés
                            kubectl get pods -n ${NAMESPACE} -l app=${APP_NAME}
                        """
                    }
                }
            }
        }
        
        stage('Tests de sécurité post-déploiement') {
            when {
                branch 'main'
            }
            steps {
                script {
                    // Vérifier les politiques de sécurité des pods
                    sh """
                        # Vérifier que les pods n'ont pas de privilèges élevés
                        kubectl get pods -n ${NAMESPACE} -l app=${APP_NAME} -o json | \
                          jq '.items[].spec.containers[].securityContext' | \
                          grep -v "privileged.*true" || echo "Pas de conteneurs privilégiés détectés"
                        
                        # Vérifier les network policies
                        kubectl get networkpolicies -n ${NAMESPACE}
                        
                        # Scanner les pods en cours d'exécution avec kubesec
                        kubectl get pod -n ${NAMESPACE} -l app=${APP_NAME} -o yaml | \
                          docker run -i kubesec/kubesec:latest scan /dev/stdin
                    """
                }
            }
        }
        
        stage('Rapport de conformité') {
            steps {
                script {
                    // Générer un rapport de conformité
                    sh """
                        echo "=== Rapport de Sécurité ===" > security-report.txt
                        echo "Build: ${BUILD_NUMBER}" >> security-report.txt
                        echo "Date: \$(date)" >> security-report.txt
                        echo "" >> security-report.txt
                        
                        echo "--- Résultats Trivy ---" >> security-report.txt
                        if [ -f trivy-report.json ]; then
                            jq '.Results[].Vulnerabilities | length' trivy-report.json >> security-report.txt
                        fi
                        
                        echo "" >> security-report.txt
                        echo "--- Résultats Snyk ---" >> security-report.txt
                        if [ -f snyk-report.json ]; then
                            jq '.vulnerabilities | length' snyk-report.json >> security-report.txt
                        fi
                        
                        echo "" >> security-report.txt
                        echo "--- État du déploiement ---" >> security-report.txt
                        kubectl get deployment ${APP_NAME} -n ${NAMESPACE} >> security-report.txt
                    """
                    
                    archiveArtifacts artifacts: 'security-report.txt', allowEmptyArchive: true
                }
            }
        }
    }
    
    post {
        always {
            // Nettoyer les images Docker locales
            sh "docker rmi ${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER} || true"
            sh "docker rmi ${DOCKER_REGISTRY}/${APP_NAME}:latest || true"
            
            // Nettoyer les fichiers temporaires
            sh "rm -f temp-deployment.yaml"
        }
        
        failure {
            // Notification en cas d'échec
            emailext (
                subject: "Pipeline Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: """
                    Le pipeline a échoué pour le build ${env.BUILD_NUMBER}.
                    
                    Vérifiez les logs: ${env.BUILD_URL}console
                    
                    Derniers commits:
                    ${currentBuild.changeSets}
                """,
                to: 'team@example.com'
            )
        }
        
        success {
            // Notification en cas de succès
            emailext (
                subject: "Pipeline Success: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: """
                    Le déploiement a réussi pour le build ${env.BUILD_NUMBER}.
                    
                    Image déployée: ${DOCKER_REGISTRY}/${APP_NAME}:${BUILD_NUMBER}
                    Namespace: ${NAMESPACE}
                    
                    Rapport de sécurité disponible dans les artifacts.
                """,
                to: 'team@example.com'
            )
        }
    }
}

// Paramètres du pipeline
properties([
    parameters([
        booleanParam(
            name: 'RUN_ZAP_SCAN',
            defaultValue: true,
            description: 'Exécuter le scan OWASP ZAP'
        ),
        choice(
            name: 'DEPLOY_ENV',
            choices: ['dev', 'staging', 'production'],
            description: 'Environnement de déploiement'
        )
    ])
])
