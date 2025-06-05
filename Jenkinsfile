pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                echo 'Récupération du code source...'
                // Si vous utilisez Git
                git branch: 'main', url: 'https://github.com/votre-user/votre-repo.git'
                // Ou si le code est déjà sur le serveur Jenkins
                // checkout scm
            }
        }
        
        stage('Build') {
            steps {
                echo 'Compilation du projet...'
                // Pour un projet Maven
                sh 'mvn clean compile'
                // Pour un projet Gradle
                // sh './gradlew build'
                // Pour un projet Node.js
                // sh 'npm install && npm run build'
            }
        }
        
        stage('Tests') {
            steps {
                echo 'Exécution des tests...'
                // Pour Maven
                sh 'mvn test'
                // Pour Gradle
                // sh './gradlew test'
                // Pour Node.js
                // sh 'npm test'
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                echo 'Analyse SonarQube...'
                withSonarQubeEnv('SonarQube-Server') {
                    // Pour Maven
                    sh 'mvn sonar:sonar'
                    // Pour Gradle
                    // sh './gradlew sonarqube'
                    // Pour autres projets avec sonar-scanner
                    // sh 'sonar-scanner'
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                echo 'Vérification Quality Gate...'
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }
    
    post {
        success {
            echo 'Pipeline exécuté avec succès!'
        }
        failure {
            echo 'Le pipeline a échoué.'
        }
        always {
            echo 'Nettoyage...'
            // Archiver les résultats si nécessaire
            // archiveArtifacts artifacts: 'target/*.jar', allowEmptyArchive: true
        }
    }
}
