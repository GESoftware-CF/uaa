package org.cloudfoundry.identity.uaa.db;


/**
 * Encodes the defaults for a given database platform.
 */
public enum DatabasePlatform {

    POSTGRESQL("postgresql", "select 1"),
    MYSQL("mysql", "select 1"),
    HSQLDB("hsqldb", "select 1 from information_schema.system_users");

    public final String type;
    public final String validationQuery;

    DatabasePlatform(String type, String validationQuery) {
        this.type = type;
        this.validationQuery = validationQuery;
    }
}
