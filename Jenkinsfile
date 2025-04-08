pipeline {
    agent any
    
    environment {
        IMAGE_NAME = 'monapp'
        IMAGE_TAG = 'latest'
    }
    
    stages {
        stage('Execute') {
            steps {
                echo '🛠️ Exécution initiale...'
                sh 'echo "Commande exécutée avant build."'
            }
        }
        
        stage('Build') {
            steps {
                echo '📦 Construction de l\'image Docker...'
                sh 'docker build -t $IMAGE_NAME:$IMAGE_TAG .'
            }
        }
        
        stage('Test') {
            steps {
                echo '🧪 Exécution des tests...'
                sh 'echo "Tests exécutés (à remplacer par de vrais tests)"'
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                echo '🔎 Analyse de code avec SonarQube...'
                withSonarQubeEnv('SonarQube') {
                    sh '''
                        SCANNER_HOME=/var/lib/jenkins/tools/hudson.plugins.sonar.SonarRunnerInstallation/SonarQube
                        $SCANNER_HOME/bin/sonar-scanner \
                        -Dsonar.projectKey=monapp \
                        -Dsonar.projectName='Mon Application' \
                        -Dsonar.sources=. \
                        -Dsonar.host.url=${SONAR_HOST_URL} \
                        -Dsonar.login=${SONAR_AUTH_TOKEN} \
                        -Dsonar.exclusions=**/node_modules/**,**/vendor/**
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
        
        stage('Scan') {
            steps {
                echo '🔍 Scan de sécurité avec Trivy...'
                sh 'trivy image --severity CRITICAL,HIGH $IMAGE_NAME:$IMAGE_TAG'
            }
        }
        
        stage('Deploy') {
            steps {
                echo '🚀 Déploiement de l\'application...'
                sh 'docker rm -f monapp_container || true'
                sh 'docker run -d --name monapp_container -p 8080:80 $IMAGE_NAME:$IMAGE_TAG'
            }
        }
    }
    
    post {
        success {
            echo '✅ Pipeline exécuté avec succès!'
        }
        failure {
            echo '❌ Le pipeline a échoué.'
        }
        always {
            echo 'Nettoyage et finalisation...'
        }
    }
}
