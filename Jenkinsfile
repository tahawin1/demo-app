pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = 'docker.io'  // Changez selon votre registry
        DOCKER_CREDENTIALS = 'docker-hub-credentials'
        SONARQUBE_SERVER = 'SonarQube'
        KUBECONFIG_CREDENTIALS = 'kubeconfig-credentials'
        NAMESPACE = 'production'
        APP_NAME = 'demo-app'
        TRIVY_SEVERITY = 'CRITICAL,HIGH'
        // Snyk token sera récupéré différemment
    }
    
    stages {
        stage('Checkout SCM') {
            steps {
                checkout scm
                echo "Code source récupéré depuis ${env.GIT_BRANCH}"
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    // Construction de l'image Docker
                    sh """
                        docker build -t ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER} .
                        docker tag ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER} ${env.DOCKER_REGISTRY}/${env.APP_NAME}:latest
                    """
                }
            }
        }
        
        stage('Analyse SonarQube') {
            when {
                expression { fileExists('sonar-project.properties') }
            }
            steps {
                script {
                    try {
                        withSonarQubeEnv(SONARQUBE_SERVER) {
                            sh '''
                                sonar-scanner \
                                  -Dsonar.projectKey=${APP_NAME} \
                                  -Dsonar.sources=. \
                                  -Dsonar.host.url=$SONAR_HOST_URL \
                                  -Dsonar.login=$SONAR_AUTH_TOKEN
                            '''
                        }
                    } catch (Exception e) {
                        echo "SonarQube analysis skipped: ${e.message}"
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            when {
                expression { fileExists('sonar-project.properties') }
            }
            steps {
                script {
                    try {
                        timeout(time: 1, unit: 'HOURS') {
                            waitForQualityGate abortPipeline: false
                        }
                    } catch (Exception e) {
                        echo "Quality Gate check skipped: ${e.message}"
                    }
                }
            }
        }
        
        stage('Scan des vulnérabilités - Trivy') {
            steps {
                script {
                    // Installation de Trivy si nécessaire
                    sh '''
                        if ! command -v trivy &> /dev/null; then
                            echo "Installation de Trivy..."
                            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
                            sudo apt-get update
                            sudo apt-get install -y trivy
                        fi
                    '''
                    
                    // Scan avec Trivy
                    def scanResult = sh(
                        script: """
                            trivy image --severity ${env.TRIVY_SEVERITY} \
                              --no-progress \
                              --format json \
                              --output trivy-report.json \
                              ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER}
                        """,
                        returnStatus: true
                    )
                    
                    // Archiver le rapport
                    if (fileExists('trivy-report.json')) {
                        archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
                    }
                    
                    if (scanResult != 0) {
                        error "Vulnérabilités critiques détectées par Trivy!"
                    }
                }
            }
        }
        
        stage('Scan des dépendances - Snyk') {
            when {
                expression { 
                    try {
                        withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
                            return true
                        }
                    } catch (Exception e) {
                        echo "Snyk token not configured, skipping Snyk scan"
                        return false
                    }
                }
            }
            steps {
                script {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
                        // Installation de Snyk si nécessaire
                        sh '''
                            if ! command -v snyk &> /dev/null; then
                                echo "Installation de Snyk..."
                                npm install -g snyk
                            fi
                        '''
                        
                        sh """
                            snyk auth ${SNYK_TOKEN}
                            snyk container test ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER} \
                              --severity-threshold=high \
                              --json > snyk-report.json || true
                        """
                        
                        if (fileExists('snyk-report.json')) {
                            // Vérifier les vulnérabilités critiques
                            def snykReport = readJSON file: 'snyk-report.json'
                            if (snykReport.vulnerabilities?.any { it.severity == 'critical' }) {
                                error "Vulnérabilités critiques détectées par Snyk!"
                            }
                            archiveArtifacts artifacts: 'snyk-report.json', allowEmptyArchive: true
                        }
                    }
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
                    withCredentials([usernamePassword(
                        credentialsId: env.DOCKER_CREDENTIALS,
                        usernameVariable: 'DOCKER_USER',
                        passwordVariable: 'DOCKER_PASS'
                    )]) {
                        sh """
                            echo ${DOCKER_PASS} | docker login ${env.DOCKER_REGISTRY} -u ${DOCKER_USER} --password-stdin
                            docker push ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER}
                            docker push ${env.DOCKER_REGISTRY}/${env.APP_NAME}:latest
                            docker logout ${env.DOCKER_REGISTRY}
                        """
                    }
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
                    // Créer le manifeste de déploiement Kubernetes
                    writeFile file: 'k8s-deployment.yaml', text: """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${env.APP_NAME}
  namespace: ${env.NAMESPACE}
  labels:
    app: ${env.APP_NAME}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ${env.APP_NAME}
  template:
    metadata:
      labels:
        app: ${env.APP_NAME}
        version: "${env.BUILD_NUMBER}"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: ${env.APP_NAME}
        image: ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER}
        ports:
        - containerPort: 8080
          name: http
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: ${env.APP_NAME}
  namespace: ${env.NAMESPACE}
spec:
  selector:
    app: ${env.APP_NAME}
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  type: LoadBalancer
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${env.APP_NAME}-netpol
  namespace: ${env.NAMESPACE}
spec:
  podSelector:
    matchLabels:
      app: ${env.APP_NAME}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ${env.NAMESPACE}
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 53  # DNS
    - protocol: UDP
      port: 53  # DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: ${env.NAMESPACE}
"""
                    
                    // Déployer sur Kubernetes
                    withCredentials([file(credentialsId: env.KUBECONFIG_CREDENTIALS, variable: 'KUBECONFIG')]) {
                        sh """
                            # Créer le namespace s'il n'existe pas
                            kubectl create namespace ${env.NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
                            
                            # Appliquer les manifestes
                            kubectl apply -f k8s-deployment.yaml
                            
                            # Attendre que le déploiement soit prêt
                            kubectl rollout status deployment/${env.APP_NAME} -n ${env.NAMESPACE} --timeout=5m
                            
                            # Afficher l'état du déploiement
                            kubectl get deployment,pods,svc -n ${env.NAMESPACE} -l app=${env.APP_NAME}
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
                    withCredentials([file(credentialsId: env.KUBECONFIG_CREDENTIALS, variable: 'KUBECONFIG')]) {
                        // Vérifier les politiques de sécurité
                        sh """
                            echo "=== Vérification de la sécurité des pods ==="
                            
                            # Vérifier que les pods n'ont pas de privilèges élevés
                            kubectl get pods -n ${env.NAMESPACE} -l app=${env.APP_NAME} -o jsonpath='{range .items[*]}{.metadata.name}{" securityContext: "}{.spec.containers[*].securityContext}{"\n"}{end}'
                            
                            # Vérifier les network policies
                            echo -e "\n=== Network Policies ==="
                            kubectl get networkpolicies -n ${env.NAMESPACE}
                            
                            # Vérifier les ressources
                            echo -e "\n=== Utilisation des ressources ==="
                            kubectl top pods -n ${env.NAMESPACE} -l app=${env.APP_NAME} || echo "Metrics server not installed"
                        """
                    }
                }
            }
        }
        
        stage('Rapport de conformité') {
            steps {
                script {
                    sh """
                        echo "=== Rapport de Sécurité ===" > security-report.txt
                        echo "Build: ${env.BUILD_NUMBER}" >> security-report.txt
                        echo "Date: \$(date)" >> security-report.txt
                        echo "Image: ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER}" >> security-report.txt
                        echo "" >> security-report.txt
                        
                        if [ -f trivy-report.json ]; then
                            echo "--- Résultats Trivy ---" >> security-report.txt
                            jq -r '.Results[0].Vulnerabilities | if . then length else 0 end' trivy-report.json >> security-report.txt || echo "0" >> security-report.txt
                        fi
                        
                        if [ -f snyk-report.json ]; then
                            echo -e "\n--- Résultats Snyk ---" >> security-report.txt
                            jq -r '.vulnerabilities | if . then length else 0 end' snyk-report.json >> security-report.txt || echo "0" >> security-report.txt
                        fi
                        
                        echo -e "\n--- État du déploiement ---" >> security-report.txt
                        echo "Déploiement réussi sur Kubernetes" >> security-report.txt
                    """
                    
                    if (fileExists('security-report.txt')) {
                        archiveArtifacts artifacts: 'security-report.txt', allowEmptyArchive: true
                    }
                }
            }
        }
    }
    
    post {
        always {
            script {
                // Nettoyer les images Docker locales
                sh """
                    docker rmi ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER} || true
                    docker rmi ${env.DOCKER_REGISTRY}/${env.APP_NAME}:latest || true
                """
                
                // Nettoyer les fichiers temporaires
                sh "rm -f k8s-deployment.yaml security-report.txt || true"
            }
        }
        
        failure {
            echo "Pipeline failed for build ${env.BUILD_NUMBER}"
            // Notification peut être ajoutée ici si nécessaire
        }
        
        success {
            echo "Pipeline succeeded! Image ${env.DOCKER_REGISTRY}/${env.APP_NAME}:${env.BUILD_NUMBER} deployed to ${env.NAMESPACE}"
        }
    }
}
