String getWarFileName() {
    // NOTE: ci-deploy.sh used by DeployJenkinsfile depends on this name format
    return "cloudfoundry-identity-uaa-${getAppVersion()}.war"
}

String getAppVersion() {
    sh (returnStdout: true, script: "grep version uaa/gradle.properties | sed 's/version=//'").trim()
}

String getArtifactoryPath() {
    // Choose transient artifactory location for all artifacts except those from release branches
    ARTIFACTORY_ROOT_FOLDER = 'pgog-fss-iam-uaa-mvn-snapshot'
    ARTIFACTORY_SUB_FOLDER = "builds/uaa/${env.BRANCH_NAME}"

    if("${env.BRANCH_NAME}" ==~ 'release_.+') {
        ARTIFACTORY_ROOT_FOLDER = 'pgog-fss-iam-uaa-mvn'
        ARTIFACTORY_SUB_FOLDER = "org/cloudfoundry/identity/cloudfoundry-identity-uaa/${getAppVersion()}"
    }
    return "${ARTIFACTORY_ROOT_FOLDER}/${ARTIFACTORY_SUB_FOLDER}"
}

return this
