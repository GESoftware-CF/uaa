package org.cloudfoundry.identity.uaa.db.beans;

import org.cloudfoundry.identity.uaa.db.DatabasePlatform;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.PropertySource;

/**
 * Configuration properties for the database so that they can be injected into various beans.
 * For each platform, defaults are encoded either in {@code application-{PLATFORM}.properties} files when they
 * can be overridden by users, or in {@link DatabasePlatform} when they are static.
 * <p>
 * Note that we reference property sources directly here, without relying on Boot auto-discovery. We do this so
 * that all configuration is visible from a single place.
 */
@Configuration
@EnableConfigurationProperties(DatabaseProperties.class)
public class DatabaseConfiguration {

    // Default profile
    @Configuration
    @Profile("!(postgresql | mysql)")
    @PropertySource("classpath:application-hsqldb.properties")
    public static class DefaultConfiguration {

    }

    @Configuration
    @Profile("postgresql")
    // The property source location is already inferred by the profile but we make it explicit
    @PropertySource("classpath:application-postgresql.properties")
    public static class PostgresConfiguration {
    }

    @Configuration
    @Profile("mysql")
    // The property source location is already inferred by the profile but we make it explicit
    @PropertySource("classpath:application-mysql.properties")
    public static class MysqlConfiguration {

    }

}
