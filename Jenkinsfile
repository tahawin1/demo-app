pipeline {
    agent any
    
    environment {
        // Configurations générales
        APP_NAME = 'demo-app'
        DOCKER_IMAGE = "${APP_NAME}:${BUILD_NUMBER}"
        REGISTRY_URL = 'registry.example.com'  // À remplacer par votre registry
        REGISTRY_CREDENTIALS = 'registry-credentials'  // ID des credentials Jenkins
        SONARQUBE_INSTALLATION = 'sonarQube'
        
        // Credentials pour Cosign
        COSIGN_PASSWORD = credentials('cosign-password')
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo "Clonage du dépôt..."
                git 'https://github.com/tahawin1/demo-app'
            }
        }
        
        stage('Installation des outils') {
            steps {
                echo "Installation des outils de sécurité..."
                sh '''
                # Vérifier et installer Cosign
                if ! command -v cosign &> /dev/null; then
                    echo "Installation de Cosign..."
                    curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
                    chmod +x cosign-linux-amd64 
                    sudo mv cosign-linux-amd64 /usr/local/bin/cosign
                fi
                
                # Vérifier et installer Trivy
                if ! command -v trivy &> /dev/null; then
                    echo "Installation de Trivy..."
                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
                fi
                
                # Vérifier et installer Snyk
                if ! command -v snyk &> /dev/null; then
                    echo "Installation de Snyk..."
                    npm install -g snyk
                fi
                
                # Télécharger OWASP ZAP
                if [ ! -d "/opt/zaproxy" ]; then
                    echo "Installation de OWASP ZAP..."
                    mkdir -p /tmp/zap
                    curl -L https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz -o /tmp/zap/zap.tar.gz
                    tar -xzf /tmp/zap/zap.tar.gz -C /tmp/zap
                    sudo mv /tmp/zap/ZAP_2.14.0 /opt/zaproxy
                    sudo ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap
                fi
                '''
            }
        }
        
        stage('Generate/Retrieve Cosign Keys') {
            steps {
                echo 'Configuration des clés Cosign...'
                
                // Créer un répertoire pour les clés
                sh 'mkdir -p /tmp/cosign-keys'
                
                // Option 1: Génération de nouvelles clés si elles n'existent pas
                script {
                    def keyExists = fileExists '/tmp/cosign-keys/cosign.key'
                    if (!keyExists) {
                        withCredentials([string(credentialsId: 'cosign-password', variable: 'COSIGN_PWD')]) {
                            sh '''
                            echo $COSIGN_PWD | cosign generate-key-pair --output-key-prefix /tmp/cosign-keys/cosign
                            chmod 600 /tmp/cosign-keys/cosign.key
                            '''
                        }
                    }
                }
                
                // Option 2: Récupération des clés existantes (décommentez si vous préférez cette approche)
                /*
                withCredentials([
                    file(credentialsId: 'cosign-private-key', variable: 'PRIVATE_KEY_FILE'),
                    file(credentialsId: 'cosign-public-key', variable: 'PUBLIC_KEY_FILE')
                ]) {
                    sh '''
                    cp $PRIVATE_KEY_FILE /tmp/cosign-keys/cosign.key
                    cp $PUBLIC_KEY_FILE /tmp/cosign-keys/cosign.pub
                    chmod 600 /tmp/cosign-keys/cosign.key
                    '''
                }
                */
                
                // Définir les chemins pour utilisation ultérieure
                script {
                    env.COSIGN_PRIVATE_KEY = '/tmp/cosign-keys/cosign.key'
                    env.COSIGN_PUBLIC_KEY = '/tmp/cosign-keys/cosign.pub'
                }
            }
        }
        
        stage('Analyse SonarQube') {
            steps {
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
            }
        }
        
        stage('Snyk Scan') {
            steps {
                echo 'Analyse des dépendances avec Snyk...'
                withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
                    sh '''
                    snyk auth $SNYK_TOKEN
                    snyk test --json > snyk-report.json || true
                    '''
                }
            }
        }
        
        stage('Analyse SCA - Trivy FS Scan') {
            steps {
                echo 'Analyse des dépendances (SCA) avec Trivy...'
                sh '''
                trivy fs --scanners vuln,license,secret . > trivy-sca-report.txt
                cat trivy-sca-report.txt
                '''
            }
        }
        
        stage('Build Docker Image') {
            steps {
                echo 'Construction de l\'image Docker...'
                sh "docker build -t ${DOCKER_IMAGE} ."
                sh "docker tag ${DOCKER_IMAGE} ${REGISTRY_URL}/${DOCKER_IMAGE}"
            }
        }
        
        stage('Trivy Container Scan') {
            steps {
                echo 'Scan de l\'image Docker avec Trivy...'
                sh '''
                trivy image --severity HIGH,CRITICAL ${DOCKER_IMAGE} > trivy-image-report.txt
                cat trivy-image-report.txt
                '''
            }
        }
        
        stage('Sign Docker Image with Cosign') {
            steps {
                echo 'Signature de l\'image Docker avec Cosign...'
                sh '''
                echo $COSIGN_PASSWORD | cosign sign --key ${COSIGN_PRIVATE_KEY} ${DOCKER_IMAGE}
                '''
                
                // Vérification de la signature
                sh '''
                cosign verify --key ${COSIGN_PUBLIC_KEY} ${DOCKER_IMAGE}
                '''
            }
        }
        
        stage('Push to Registry') {
            steps {
                echo 'Push de l\'image vers le registry...'
                withCredentials([usernamePassword(credentialsId: "${REGISTRY_CREDENTIALS}", passwordVariable: 'REGISTRY_PASSWORD', usernameVariable: 'REGISTRY_USERNAME')]) {
                    sh '''
                    echo $REGISTRY_PASSWORD | docker login ${REGISTRY_URL} -u $REGISTRY_USERNAME --password-stdin
                    docker push ${REGISTRY_URL}/${DOCKER_IMAGE}
                    '''
                }
                
                // Signature de l'image dans le registry (optionnel)
                sh '''
                echo $COSIGN_PASSWORD | cosign sign --key ${COSIGN_PRIVATE_KEY} ${REGISTRY_URL}/${DOCKER_IMAGE}
                '''
            }
        }
        
        stage('OPA/Gatekeeper Validation') {
            steps {
                echo 'Validation des policies avec OPA...'
                sh '''
                # Vérifier si OPA est installé
                if ! command -v opa &> /dev/null; then
                    curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
                    chmod 755 /usr/local/bin/opa
                fi
                
                # Créer un fichier de policy exemple si nécessaire
                cat > policy.rego << 'EOL'
                package kubernetes.admission
                
                deny[msg] {
                    input.request.kind.kind == "Pod"
                    not input.request.object.spec.securityContext.runAsNonRoot
                    msg := "Pods must run as non-root user"
                }
                EOL
                
                # Créer un fichier d'exemple pour test
                cat > pod.json << 'EOL'
                {
                  "apiVersion": "v1",
                  "kind": "Pod",
                  "metadata": {
                    "name": "example"
                  },
                  "spec": {
                    "containers": [
                      {
                        "name": "example",
                        "image": "nginx"
                      }
                    ]
                  }
                }
                EOL
                
                # Exécuter l'évaluation
                opa eval --format pretty --data policy.rego --input pod.json "data.kubernetes.admission.deny" > opa-report.txt || true
                cat opa-report.txt
                '''
            }
        }
        
        stage('OWASP ZAP DAST Scan') {
            steps {
                echo 'Scan DAST avec OWASP ZAP...'
                sh '''
                # Utiliser ZAP dans Docker pour éviter les problèmes d'installation
                docker run --rm -v $(pwd):/zap/wrk/:rw owasp/zap2docker-stable zap-baseline.py \
                    -t http://example.com -g gen.conf -r zap-report.html || true
                # Note: Remplacer example.com par l'URL de votre application déployée
                '''
            }
        }
    }
    
    post {
        always {
            // Archiver les rapports
            archiveArtifacts artifacts: '*-report.*', fingerprint: true
            
            // Nettoyage
            sh '''
            # Nettoyage des fichiers temporaires
            rm -rf /tmp/cosign-keys
            
            # Supprimer les images Docker locales pour libérer de l'espace
            docker rmi ${DOCKER_IMAGE} ${REGISTRY_URL}/${DOCKER_IMAGE} || true
            '''
        }
        success {
            echo '✅ Pipeline complet: Toutes les étapes de sécurité, signature et déploiement réussies.'
        }
        failure {
            echo '❌ Échec dans le pipeline: Vérifiez les logs pour plus de détails.'
        }
    }
}
