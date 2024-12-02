package org.cloudfoundry.identity.uaa.db;

public class UaaDatabaseName {
    private static final String UAA_DB_NAME = "uaa";

    private final String gradleWorkerId;

    public UaaDatabaseName(String gradleWorkerId) {
        this.gradleWorkerId = gradleWorkerId;
    }

    public String getName() {
        if (gradleWorkerId == null) {
            return UAA_DB_NAME;
        }

        return UAA_DB_NAME + "_" + gradleWorkerId;
    }

    // TODO dgarnier
    // This is a test utility and should not be a prod class
    public static String getDbNameFromSystemProperties() {
        var gradleWorkerId = System.getProperty("org.gradle.test.worker");
        if (gradleWorkerId == null) {
            return UAA_DB_NAME;
        }

        return UAA_DB_NAME + "_" + gradleWorkerId;
    }
}
