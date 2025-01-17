/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;

public class DatabaseUrlModifier {

    private final DatabasePlatform databasePlatform;
    private final String url;
    private int connectTimeoutSeconds = 10;

    public DatabaseUrlModifier(DatabasePlatform databasePlatform, String url) {
        if (databasePlatform == null) {
            throw new NullPointerException();
        }

        this.databasePlatform = databasePlatform;
        this.url = url;
    }

    public int getConnectTimeoutSeconds() {
        return connectTimeoutSeconds;
    }

    public void setConnectTimeoutSeconds(int connectTimeoutSeconds) {
        this.connectTimeoutSeconds = connectTimeoutSeconds;
    }

    public DatabasePlatform getDatabasePlatform() {
        return this.databasePlatform;
    }

    public String getUrl() {
        StringBuilder result = new StringBuilder(url);
        switch (getDatabasePlatform()) {
            case MYSQL: {
                appendParameter(result, "connectTimeout", getConnectTimeoutSeconds() * 1000);
                break;
            }
            case POSTGRESQL: {
                appendParameter(result, "connectTimeout", getConnectTimeoutSeconds());
                break;
            }
            case HSQLDB:
                break;
        }
        return result.toString();
    }

    private void appendParameter(StringBuilder result, String name, Object value) {
        if (result.indexOf("?") > 0) {
            result.append("&");
        } else {
            result.append("?");
        }
        result.append(name);
        result.append("=");
        result.append(value.toString());
    }
}
