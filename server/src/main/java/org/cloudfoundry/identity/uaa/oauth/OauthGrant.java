package org.cloudfoundry.identity.uaa.oauth;

public enum OauthGrant {
    JWT_BEARER("jwt_bearer"),
    CLIENT_CREDENTIALS("client_credentials"),
    PASSWORD("password"),
    IMPLICIT("implicit"),
    AUTHORIZTION_CODE("authorization_code"),
    REFRESH_TOKEN("refresh_token")
    ;
    
    private final String value;
    
    OauthGrant(String value) {
        this.value = value;
    }
    
    public String value() {
        return this.value;
    }
 }
