        stage('Signature avec Cosign') {
            steps {
                echo '🔐 Signature de l’image avec Cosign...'
                withCredentials([file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY')]) {
                    script {
                        // Récupérer le digest de l’image pour une signature fiable
                        def digest = sh(script: "docker inspect --format='{{index .RepoDigests 0}}' demo-app:latest", returnStdout: true).trim()
                        sh "cosign sign --key $COSIGN_KEY ${digest}"
                    }
                }
            }
        }

        stage('Vérification de la signature') {
            steps {
                echo '✅ Vérification de la signature avec Cosign...'
                script {
                    def digest = sh(script: "docker inspect --format='{{index .RepoDigests 0}}' demo-app:latest", returnStdout: true).trim()
                    sh "cosign verify --key /var/jenkins_home/cosign.pub ${digest}"
                }
            }
        }
