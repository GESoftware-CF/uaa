package org.cloudfoundry.identity.uaa.provider.token;

import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;

public class MockAssertionToken {

    private final KeyInfo keyInfo;

    public MockAssertionToken(final String tokenSigningKey) {
        this.keyInfo = new KeyInfo(null, tokenSigningKey, "https://localhost", JWSAlgorithm.RS256.getName(), null);
    }

    /**
     * Create a mock with D1 signer
     */
    public MockAssertionToken() {
        this.keyInfo = new KeyInfo(null, MockKeyProvider.DEVICE1_PRIVATE_KEY, "https://localhost");
    }

    public MockAssertionToken(RSAPrivateKey tokenSigningKey) {
        // Convert RSAPrivateKey to PEM format for KeyInfo
        this.keyInfo = new KeyInfo(null, convertToPem(tokenSigningKey), "https://localhost");
    }

    public String mockAssertionToken(String issuer, final String subject, final long issuedAtMillis,
                                     final long validitySeconds, final String tenantId, final Object audience) {
        Object expiration = (issuedAtMillis + (validitySeconds * 1000L)) / 1000L;
        return createAssertionToken(issuer, subject, audience, issuedAtMillis, tenantId, expiration);
    }

    public String mockInvalidExpirationAssertionToken(String issuer, final String subject,
                                                      final long issuedAtMillis, final String tenantId, final Object audience, final Object expiration) {
        return createAssertionToken(issuer, subject, audience, issuedAtMillis, tenantId, expiration);
    }

    private String createAssertionToken(String issuer, String subject, Object audience,
                                        final long issuedAtMillis, final String tenantId, final Object expiration) {
        Map<String, Object> claims = createClaims(issuer, subject, audience, issuedAtMillis, expiration, tenantId);
        Jwt token = JwtHelper.encode(claims, this.keyInfo);
        return token.getEncoded();
    }

    static Map<String, Object> createClaims(String issuer, String subject, final Object audience,
                                       final long issuedAtMillis, final Object expiration, final String tenantId) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(ClaimConstants.ISS, issuer);
        response.put(ClaimConstants.SUB, subject);
        response.put(ClaimConstants.TENANT_ID, tenantId);
        response.put(ClaimConstants.IAT, issuedAtMillis / 1000L);

        if (expiration != null) {
            response.put(ClaimConstants.EXPIRY_IN_SECONDS, expiration);
        }
        response.put(ClaimConstants.AUD, audience);

        return response;
    }

    private String convertToPem(RSAPrivateKey privateKey) {
        // Convert RSAPrivateKey to PEM format
        java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
        String encoded = encoder.encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" +
               encoded.replaceAll("(.{64})", "$1\n") +
               "\n-----END PRIVATE KEY-----";
    }
}


