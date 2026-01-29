// SecurityUse Jenkins Pipeline
// Add this to your Jenkinsfile or Pipeline script

pipeline {
    agent any

    environment {
        PYTHON_VERSION = '3.11'
    }

    stages {
        stage('Setup') {
            steps {
                sh '''
                    python3 -m pip install --upgrade pip
                    pip install security-use
                '''
            }
        }

        stage('Security Scan') {
            parallel {
                stage('Dependency Scan') {
                    steps {
                        script {
                            def result = sh(
                                script: 'security-use scan deps . --format json',
                                returnStatus: true
                            )
                            if (result != 0) {
                                unstable('Dependency vulnerabilities found')
                            }
                        }
                    }
                }

                stage('IaC Scan') {
                    steps {
                        script {
                            def result = sh(
                                script: 'security-use scan iac . --format json',
                                returnStatus: true
                            )
                            if (result != 0) {
                                unstable('IaC security issues found')
                            }
                        }
                    }
                }
            }
        }

        stage('Generate Reports') {
            steps {
                sh '''
                    security-use scan all . --format sarif --output security-results.sarif || true
                    security-use sbom generate . --format cyclonedx-json --output sbom.json
                '''
            }
        }

        stage('Fail on Critical') {
            steps {
                sh 'security-use scan all . --severity critical'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.sarif,*.json', allowEmptyArchive: true

            // Publish JUnit-style results if available
            junit allowEmptyResults: true, testResults: '**/test-results.xml'
        }

        failure {
            echo 'Security scan failed - critical vulnerabilities found'
        }

        unstable {
            echo 'Security scan completed with warnings'
        }
    }
}
