pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git credentialsId: 'github-creds',
                    url: 'https://github.com/tahawin1/demo-app.git',
                    branch: 'main'
            }
        }
    }
}
