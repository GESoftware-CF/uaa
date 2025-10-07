package org.cloudfoundry.identity.uaa.provider.token;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class MockClientAssertionHeader {

    private final KeyInfo keyInfo;

    // Default uses device1 key (String PEM in MockKeyProvider)
    public MockClientAssertionHeader() {
        this.keyInfo = new KeyInfo(null, MockKeyProvider.DEVICE1_PRIVATE_KEY, "https://localhost");
    }

    // Accept PEM String
    public MockClientAssertionHeader(String pemPrivateKey) {
        this.keyInfo = new KeyInfo(null, pemPrivateKey, "https://localhost");
    }

    // Accept actual RSA private key
    public MockClientAssertionHeader(RSAPrivateKey signingKey) {
        String pemKey = convertToPem(signingKey);
        this.keyInfo = new KeyInfo(null, pemKey, "https://localhost");
    }

    public String mockSignedHeader(Long iat, String devicedId, String tenantId) {
        return JwtHelper.encode(createClaims(iat, devicedId, tenantId), this.keyInfo).getEncoded();
    }

    public String mockIncorrectlySignedHeader(final String devicedId, final String tenantId) {
        long currentTimeSecs = System.currentTimeMillis() / 1000;
        KeyInfo incorrect = new KeyInfo(null, MockKeyProvider.INCORRECT_TOKEN_SIGNING_KEY, "https://localhost");
        return JwtHelper.encode(createClaims(currentTimeSecs, devicedId, tenantId), incorrect).getEncoded();
    }

    private Map<String, Object> createClaims(Long iat, final String devicedId, final String tenantId) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(ClaimConstants.IAT, iat);
        response.put(ClaimConstants.SUB, devicedId);
        response.put(ClaimConstants.TENANT_ID, tenantId);
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

    private static RSAPrivateKey parseRsaPrivateKey(String pem) {
        try {
            String normalized = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(normalized);
            // Try PKCS#8 directly
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse RSA private key", e);
        }
    }
}
