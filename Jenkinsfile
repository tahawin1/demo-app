pipeline {
    agent any

    tools {
        // Assurez-vous que ces outils sont bien installés et configurés dans Jenkins
        // (Manage Jenkins > Global Tool Configuration)
        maven 'Maven'         // ou remplace par le nom exact configuré dans Jenkins
        jdk 'JDK-11'          // idem ici
    }

    environment {
        DOCKER_IMAGE = 'demo-app'
    }

    stages {
        stage('Checkout SCM') {
            steps {
                git credentialsId: 'taaha', url: 'https://github.com/tahawin1/demo-app.git', branch: 'master'
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'mvn clean verify sonar:sonar'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    sh "docker build -t ${DOCKER_IMAGE}:latest ."
                }
            }
        }

        stage('Trivy Scan') {
            steps {
                sh 'trivy image --exit-code 0 --severity CRITICAL,HIGH ${DOCKER_IMAGE}:latest'
            }
        }
    }

    post {
        always {
            echo 'Pipeline terminé.'
            sh 'docker image prune -f'
        }
        failure {
            echo 'Le pipeline a échoué.'
        }
    }
}
