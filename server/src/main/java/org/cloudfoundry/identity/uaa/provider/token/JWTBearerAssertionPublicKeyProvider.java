package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Map;

public interface JWTBearerAssertionPublicKeyProvider {

    /**
     * This method must provide the registered public key for the client requesting a jwt-bearer authorization grant.
     * This key is used to verify the signature of assertion token.
     * @param claims  from the assertion token in the grant request.
     */
    String getPublicKey(Map<String, Object> claims);

}
