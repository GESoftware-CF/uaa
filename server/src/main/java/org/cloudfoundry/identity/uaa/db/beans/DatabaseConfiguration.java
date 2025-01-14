package org.cloudfoundry.identity.uaa.db.beans;

import org.cloudfoundry.identity.uaa.db.DatabasePlatform;
import org.cloudfoundry.identity.uaa.db.DatabaseUrlModifier;
import org.cloudfoundry.identity.uaa.db.Vendor;
import org.cloudfoundry.identity.uaa.resources.jdbc.HsqlDbLimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.MySqlLimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.PostgresLimitSqlAdapter;
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.PropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;

/**
 * Configuration properties for the database so that they can be injected into various beans.
 * For each platform, defaults are encoded either in {@code application-{PLATFORM}.properties} files when they
 * can be overridden by users, or in {@link DatabasePlatform} when they are static.
 * <p>
 * Note that we reference property sources directly here, without relying on Boot auto-discovery. We do this so
 * that all configuration is visible from a single place.
 * <p>
 * The following beans are wired by Spring Boot auto-configuration.
 * <p>
 * In {@link JdbcTemplateAutoConfiguration}:
 * <ul>
 *      <li>{@link JdbcTemplate}</li>
 *      <li>{@link NamedParameterJdbcTemplate}</li>
 * </ul>
 */
@Configuration
@EnableConfigurationProperties(DatabaseProperties.class)
public class DatabaseConfiguration {

    // TODO dgarnier remove
    @Bean
    Boolean useCaseInsensitiveQueries(DatabaseProperties databaseProperties) {
        return databaseProperties.isCaseinsensitive();
    }

    // TODO dgarnier remove
    @Bean
    DatabaseUrlModifier databaseUrlModifier(DatabaseProperties databaseProperties) {
        var databaseUrlModifier = new DatabaseUrlModifier(Vendor.valueOf(databaseProperties.getType()), databaseProperties.getUrl());
        databaseUrlModifier.setConnectTimeoutSeconds(databaseProperties.getConnecttimeout());
        return databaseUrlModifier;
    }

    @Bean(destroyMethod = "close")
    org.apache.tomcat.jdbc.pool.DataSource dataSource(DatabaseUrlModifier databaseUrlModifier, DatabaseProperties databaseProperties) {
        var dataSource = new org.apache.tomcat.jdbc.pool.DataSource();
        dataSource.setDriverClassName(databaseProperties.getDriverClassName());
        dataSource.setUrl(databaseUrlModifier.getUrl());
        dataSource.setUsername(databaseProperties.getUsername());
        dataSource.setPassword(databaseProperties.getPassword());
        dataSource.setValidationInterval(databaseProperties.getValidationinterval());
        dataSource.setValidationQuery(databaseProperties.getValidationQuery());
        dataSource.setTestOnBorrow(true);
        dataSource.setTestWhileIdle(databaseProperties.isTestwhileidle());
        dataSource.setMinIdle(databaseProperties.getMinidle());
        dataSource.setMaxIdle(databaseProperties.getMaxidle());
        dataSource.setMaxActive(databaseProperties.getMaxactive());
        dataSource.setMaxWait(databaseProperties.getMaxwait());
        dataSource.setInitialSize(databaseProperties.getInitialsize());
        dataSource.setValidationQueryTimeout(databaseProperties.getValidationquerytimeout());
        dataSource.setRemoveAbandoned(databaseProperties.isRemovedabandoned());
        dataSource.setTimeBetweenEvictionRunsMillis(databaseProperties.getEvictionintervalms());
        dataSource.setMinEvictableIdleTimeMillis(databaseProperties.getMinEvictionIdleMs());
        dataSource.setJdbcInterceptors("org.cloudfoundry.identity.uaa.metrics.QueryFilter(threshold=3000)");
        return dataSource;
    }

    // Default profile
    @Configuration
    @Profile("!(postgresql | mysql)")
    @PropertySource("classpath:application-hsqldb.properties")
    public static class DefaultConfiguration {

        @Bean
        LimitSqlAdapter limitSqlAdapter() {
            return new HsqlDbLimitSqlAdapter();
        }

    }

    @Configuration
    @Profile("postgresql")
    // The property source location is already inferred by the profile but we make it explicit
    @PropertySource("classpath:application-postgresql.properties")
    public static class PostgresConfiguration {

        @Bean
        LimitSqlAdapter limitSqlAdapter() {
            return new PostgresLimitSqlAdapter();
        }

    }

    @Configuration
    @Profile("mysql")
    // The property source location is already inferred by the profile but we make it explicit
    @PropertySource("classpath:application-mysql.properties")
    public static class MysqlConfiguration {

        @Bean
        LimitSqlAdapter limitSqlAdapter() {
            return new MySqlLimitSqlAdapter();
        }

    }

}
