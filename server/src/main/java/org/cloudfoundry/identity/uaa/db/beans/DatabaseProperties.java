package org.cloudfoundry.identity.uaa.db.beans;

import org.cloudfoundry.identity.uaa.db.DatabasePlatform;
import org.cloudfoundry.identity.uaa.db.UaaDatabaseName;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Represents a subset of the configurable properties for the database, either through
 * end-user config, or through profiles.
 * <p>
 * TODO(dgarnier): remove the @Component annotationm added so that this class is consumable in XML configuration.
 */
@Component
@ConfigurationProperties(prefix = "database")
public class DatabaseProperties implements EnvironmentAware {

    private String driverClassName;
    private String username;
    private String password;
    private String url;
    private int maxParameters;
    private boolean useSkipLocked;
    private boolean caseinsensitive;
    private DatabasePlatform platform;
    private String defaultUrl;

    public void setCaseinsensitive(boolean caseinsensitive) {
        this.caseinsensitive = caseinsensitive;
    }

    public void setUseSkipLocked(boolean useSkipLocked) {
        this.useSkipLocked = useSkipLocked;
    }

    public void setMaxParameters(int maxParameters) {
        this.maxParameters = maxParameters;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setDriverClassName(String driverClassName) {
        this.driverClassName = driverClassName;
    }

    public String getUsername() {
        return this.username;
    }

    public String getDriverClassName() {
        return this.driverClassName;
    }

    public String getPassword() {
        return this.password;
    }

    public String getUrl() {
        return this.url != null ? this.url : this.defaultUrl;
    }

    public int getMaxParameters() {
        return this.maxParameters;
    }

    public boolean isUseSkipLocked() {
        return this.useSkipLocked;
    }

    public boolean isCaseinsensitive() {
        return this.caseinsensitive;
    }

    public String getType() {
        return this.platform.type;
    }

    public String getValidationQuery() {
        return this.platform.validationQuery;
    }

    @Override
    public void setEnvironment(Environment environment) {
        var profiles = environment.getActiveProfiles();
        var dbName = UaaDatabaseName.getDbNameFromSystemProperties();
        for (var profile : profiles) {
            switch (profile) {
                case "postgresql":
                    this.platform = DatabasePlatform.POSTGRESQL;
                    this.defaultUrl = "jdbc:postgresql:%s".formatted(dbName);
                    return;
                case "mysql":
                    this.platform = DatabasePlatform.MYSQL;
                    this.defaultUrl = "jdbc:mysql://127.0.0.1:3306/%s?useSSL=true&trustServerCertificate=true".formatted(dbName);
                    return;
            }
        }
        this.platform = DatabasePlatform.HSQLDB;
        this.defaultUrl = "jdbc:hsqldb:mem:%s".formatted(dbName);

    }
}
