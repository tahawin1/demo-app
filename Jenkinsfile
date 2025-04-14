pipeline {
    agent any

    stages {
        stage('Install Trivy and Cosign') {
            steps {
                script {
                    // Installer Trivy
                    sh 'curl -sfL https://github.com/aquasecurity/trivy/releases/download/v0.29.1/trivy_0.29.1_Linux-64bit.deb -o trivy.deb'
                    sh 'sudo dpkg -i trivy.deb'

                    // Installer Cosign
                    sh 'curl -sSL https://github.com/sigstore/cosign/releases/download/v1.16.0/cosign-linux-amd64 -o cosign'
                    sh 'chmod +x cosign'
                    sh 'sudo mv cosign /usr/local/bin/'
                }
            }
        }

        stage('Scan Image with Trivy') {
            steps {
                script {
                    // Scanner l'image Docker avec Trivy
                    sh 'trivy image --exit-code 1 --no-progress <your-docker-image>'
                }
            }
        }

        stage('Sign Image with Cosign') {
            steps {
                script {
                    // Signer l'image Docker avec Cosign après le scan
                    withCredentials([file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY')]) {
                        sh "cosign sign --key $COSIGN_KEY <your-docker-image>"
                    }
                }
            }
        }
    }
}
