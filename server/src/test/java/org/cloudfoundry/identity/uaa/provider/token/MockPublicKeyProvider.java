package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Map;

public class MockPublicKeyProvider implements JwtBearerAssertionPublicKeyProvider {

    @Override
    public String getPublicKey(Map<String, Object> claims) {
        return TestKeys.TOKEN_VERIFYING_KEY;
    }

}
