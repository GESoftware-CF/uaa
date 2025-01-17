package org.cloudfoundry.identity.uaa.db.beans;


import org.cloudfoundry.identity.uaa.db.DatabasePlatform;
import org.cloudfoundry.identity.uaa.db.UaaDatabaseName;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * Represents the configurable properties for the database, set either through
 * end-user config, or through profiles.
 * <p>
 * Casing is inconsistent but required by legacy configuration property names.
 */
@ConfigurationProperties(prefix = "database")
public class DatabaseProperties implements EnvironmentAware {

    private String driverClassName;
    private String username;
    private String password;
    private String url;
    private int maxParameters;
    private boolean useSkipLocked;
    private boolean caseinsensitive;
    private DatabasePlatform platform = DatabasePlatform.HSQLDB;

    // With defaults
    private String defaultUrl; // default set in setEnvironment
    private Integer connecttimeout = 10;
    private long validationinterval = 5000;
    private boolean testwhileidle = false;
    private int minidle = 0;
    private int maxidle = 10;
    private int maxactive = 100;
    private int maxwait = 30_000;
    private int initialsize = 10;
    private int validationquerytimeout = 10;
    private boolean removedAbandoned = false;
    private boolean logabandoned = true;
    private int abandonedtimeout = 300;
    private int evictionintervalms = 15_000;
    private int minevictionidlems = 60_000;

    public String getUrl() {
        return this.url != null ? this.url : this.defaultUrl;
    }

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

    public void setConnecttimeout(int connecttimeout) {
        this.connecttimeout = connecttimeout;
    }

    public void setValidationinterval(long validationinterval) {
        this.validationinterval = validationinterval;
    }

    public void setTestwhileidle(boolean testwhileidle) {
        this.testwhileidle = testwhileidle;
    }

    public void setMinidle(int minidle) {
        this.minidle = minidle;
    }

    public void setMaxidle(int maxidle) {
        this.maxidle = maxidle;
    }

    public void setMaxactive(int maxactive) {
        this.maxactive = maxactive;
    }

    public void setMaxwait(int maxwait) {
        this.maxwait = maxwait;
    }

    public void setInitialsize(int initialsize) {
        this.initialsize = initialsize;
    }

    public void setValidationquerytimeout(int validationquerytimeout) {
        this.validationquerytimeout = validationquerytimeout;
    }

    public void setRemovedabandoned(boolean removedabandoned) {
        this.removedAbandoned = removedabandoned;
    }

    public void setLogabandoned(boolean logabandoned) {
        this.logabandoned = logabandoned;
    }

    public void setAbandonedtimeout(int abandonedtimeout) {
        this.abandonedtimeout = abandonedtimeout;
    }

    public void setEvictionintervalms(int evictionintervalms) {
        this.evictionintervalms = evictionintervalms;
    }

    public void setMinevictionidlems(int minevictionidlems) {
        this.minevictionidlems = minevictionidlems;
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

    public int getMaxParameters() {
        return this.maxParameters;
    }

    public boolean isUseSkipLocked() {
        return this.useSkipLocked;
    }

    public boolean isCaseinsensitive() {
        return this.caseinsensitive;
    }

    public DatabasePlatform getDatabasePlatform() {
        return this.platform;
    }

    public String getValidationQuery() {
        return this.platform.validationQuery;
    }

    public int getConnecttimeout() {
        return this.connecttimeout;
    }

    public long getValidationinterval() {
        return validationinterval;
    }

    public int getMinEvictionIdleMs() {
        return minevictionidlems;
    }

    public int getEvictionintervalms() {
        return evictionintervalms;
    }

    public int getAbandonedtimeout() {
        return abandonedtimeout;
    }

    public boolean isLogabandoned() {
        return logabandoned;
    }

    public boolean isRemovedabandoned() {
        return removedAbandoned;
    }

    public int getValidationquerytimeout() {
        return validationquerytimeout;
    }

    public int getInitialsize() {
        return initialsize;
    }

    public int getMaxwait() {
        return maxwait;
    }

    public int getMaxactive() {
        return maxactive;
    }

    public int getMaxidle() {
        return maxidle;
    }

    public int getMinidle() {
        return minidle;
    }

    public boolean isTestwhileidle() {
        return testwhileidle;
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
