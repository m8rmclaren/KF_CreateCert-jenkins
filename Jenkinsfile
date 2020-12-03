pipeline {
    agent any
    parameters {
        string(name: 'StoreID', defaultValue: '00000000-0000-0000-0000-000000000000')
        string(name: 'CommonName', defaultValue: 'example.com')
        string(name: 'CertFormat', defaultValue: 'JKS')
        string(name: 'Password', defaultValue: 'P@ssw0rd1')
        string(name: 'CertAlias', defaultValue: 'alias')
        string(name: 'Email', defaultValue: 'person@example.com')
    }
    stages {
        stage('Request certificate from Keyfactor') {
            steps {
                echo "Calling KeyFactor"
                withEnv(['PATH+EXTRA=/usr/sbin:/usr/bin:/sbin:/bin']) {
                    sh 'echo "" > output.json'
                    sh "python3 main.py ${params.StoreID} ${params.CommonName} ${params.CertFormat} ${params.Password} ${params.CertAlias} ${params.Email}"
                    sh 'cat output.json'
                }
            }
        }
    }
}