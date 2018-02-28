#!/usr/bin/env groovy
def devcloudArtServer = Artifactory.server('devcloud')
pipeline {
    agent none
    environment {
            COMPLIANCEENABLED = true
    }
    options {
        skipDefaultCheckout()
        buildDiscarder(logRotator(artifactDaysToKeepStr: '1', artifactNumToKeepStr: '1', daysToKeepStr: '5', numToKeepStr: '10'))
    }
    parameters {
        booleanParam(name: 'UNIT_TESTS', defaultValue: true, description: 'Run Unit tests')
        booleanParam(name: 'MOCK_MVC_TESTS', defaultValue: true, description: 'Run Mock MVC tests')
        booleanParam(name: 'INTEGRATION_TESTS', defaultValue: true, description: 'Run Integration tests')
        booleanParam(name: 'DEGRADED_TESTS', defaultValue: true, description: 'Run degraded mode tests')
        booleanParam(name: 'PUSH_TO_DEVCLOUD', defaultValue: false, description: 'Publish to build artifactory')
    }
    stages {
        stage('Standalone Acceptance') {
            agent{
                docker {
                    image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.8'
                    label 'dind'
                    args '-v /var/lib/docker/.gradle:/root/.gradle'
                }
            }
            steps {
                dir('uaa') {
                    checkout scm
                }
                dir('uaa-cf-release') {
                    git changelog: false, credentialsId: 'github.build.ge.com', poll: false, url: 'https://github.build.ge.com/predix/uaa-cf-release.git', branch: 'master'
                }
                sh '''#!/bin/bash -ex
                export CF_USERNAME=$CF_CREDENTIALS_USR
                export CF_PASSWORD=$CF_CREDENTIALS_PSW
                export APP_VERSION=`grep 'version' uaa/gradle.properties | sed 's/version=//'`
                echo "APP_VERSION is:$APP_VERSION"
                export DEPLOY_BRANCH_SUFFIX=$APP_VERSION
                source uaa-cf-release/config-${DEPLOYMENT_TYPE}/set-env.sh
                unset HTTPS_PROXY
                unset HTTP_PROXY
                unset http_proxy
                unset https_proxy
                unset GRADLE_OPTS

                pushd uaa-cf-release
                    export ACCEPTANCE_SUBDOMAIN=$ACCEPTANCE_ZONE_ID-$DEPLOYMENT_TYPE
                    curl -vvv https://$ACCEPTANCE_SUBDOMAIN.${PUBLISHED_HOST}.${CF_DOMAIN} || echo 'curl acceptance subdomain failed'
                    uaac target https://$ACCEPTANCE_SUBDOMAIN.${PUBLISHED_HOST}.${CF_DOMAIN} --skip-ssl-validation
                    uaac token client get admin -s acceptance-test
                    
                    cp config-$DEPLOYMENT_TYPE/sso_metadata.xml ../uaa/uaa/src/test/resources/
                popd
                
                pushd uaa
                    ./gradlew jacocoRootReportAcceptanceTest
                popd
                '''
            }
            post{
                always {
                    publishHTML target: [
                            allowMissing: true,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: 'uaa/uaa/build/reports/tests/acceptanceTest',
                            reportFiles: 'index.html',
                            reportName: 'Acceptance Test Results'
                    ]
                    publishHTML target: [
                            allowMissing: true,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: 'uaa/build/reports/jacoco/jacocoRootReportAcceptanceTest/html',
                            reportFiles: 'index.html',
                            reportName: 'Acceptance Test Code Coverage'
                    ]
                }
            }
        }
    }
    post {
        success {
            echo 'UAA pipeline was successful. Sending notification!'
        }
        failure {
            echo "UAA pipeline failed. Sending notification!"
        }
    }

}