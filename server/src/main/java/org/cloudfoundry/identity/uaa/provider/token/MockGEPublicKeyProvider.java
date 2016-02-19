package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Map;

public class MockGEPublicKeyProvider implements JWTBearerAssertionPublicKeyProvider {

    @Override
    public String getPublicKey(Map<String, Object> claims) {
        return MockKeys.TOKEN_VERIFYING_KEY;
    }

}
