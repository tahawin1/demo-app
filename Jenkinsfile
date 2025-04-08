pipeline {
    agent any

    environment {
        SONARQUBE_SERVER = 'SonarQubeServer'     // Nom du serveur configuré dans Jenkins (Manage Jenkins > Configure system)
        DOCKER_IMAGE = 'monimage:latest'
    }

    stages {

        stage('Checkout Code') {
            steps {
                git url: 'https://github.com/ton-utilisateur/ton-projet.git', branch: 'main'
            }
        }

        stage('SonarQube Scan (SAST)') {
            steps {
                withSonarQubeEnv("${SONARQUBE_SERVER}") {
                    sh 'sonar-scanner'
                }
            }
        }

        stage('Trivy Scan - Dockerfile') {
            steps {
                sh '''
                if ! command -v trivy &> /dev/null
                then
                    echo "Trivy not found, installing..."
                    sudo apt-get update
                    sudo apt-get install wget -y
                    wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.46.1_Linux-64bit.deb
                    sudo dpkg -i trivy_0.46.1_Linux-64bit.deb
                fi

                trivy config --exit-code 0 --severity HIGH,CRITICAL .
                '''
            }
        }

        stage('Docker Build') {
            steps {
                sh 'docker build -t $DOCKER_IMAGE .'
            }
        }

        stage('Trivy Scan - Docker Image') {
            steps {
                sh 'trivy image --exit-code 0 --severity HIGH,CRITICAL $DOCKER_IMAGE'
            }
        }

        // stage('Docker Push') {
        //     steps {
        //         withCredentials([usernamePassword(credentialsId: 'dockerhub-creds', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
        //             sh '''
        //             echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin
        //             docker tag $DOCKER_IMAGE $DOCKER_USER/$DOCKER_IMAGE
        //             docker push $DOCKER_USER/$DOCKER_IMAGE
        //             '''
        //         }
        //     }
        // }

    }

    post {
        always {
            echo "Pipeline terminé. Nettoyage..."
        }
    }
}

