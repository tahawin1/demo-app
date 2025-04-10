pipeline {
    agent any
    
    stages {
        stage('Test SonarQube Connection') {
            steps {
                script {
                    try {
                        // Essaie d'accéder à l'API SonarQube
                        def response = sh(script: 'curl -s -o /dev/null -w "%{http_code}" http://localhost:9000/api/system/status', returnStdout: true).trim()
                        
                        if (response == "200") {
                            echo "✅ SonarQube est accessible (HTTP 200)"
                            
                            // Affiche les informations sur la version
                            def version = sh(script: 'curl -s http://localhost:9000/api/system/status', returnStdout: true).trim()
                            echo "Info SonarQube: ${version}"
                            
                            // Vérifie si l'installation de SonarQube est correctement configurée dans Jenkins
                            def sonarInstallation = tool name: 'SonarQube', type: 'hudson.plugins.sonar.SonarRunnerInstallation'
                            if (sonarInstallation) {
                                echo "✅ L'installation SonarQube est configurée dans Jenkins"
                            } else {
                                echo "❌ Aucune installation SonarQube nommée 'SonarQube' n'est configurée dans Jenkins"
                            }
                        } else {
                            echo "❌ SonarQube n'est pas accessible (HTTP ${response})"
                        }
                    } catch (Exception e) {
                        echo "❌ Erreur lors de la vérification de SonarQube: ${e.message}"
                    }
                }
            }
        }
    }
}
