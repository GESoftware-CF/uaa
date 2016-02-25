package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;

public class JwtBearerAssertionTokenAuthenticator {

    private final Log logger = LogFactory.getLog(getClass());
    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider clientPublicKeyProvider;
    private final int maxAcceptableClockSkewSeconds = 60;
    
    private final String issuerURL;
    
    public JwtBearerAssertionTokenAuthenticator(String issuerURL) {
        this.issuerURL = issuerURL;
    }

    public void setClientPublicKeyProvider(DevicePublicKeyProvider clientPublicKeyProvider) {
        this.clientPublicKeyProvider = clientPublicKeyProvider;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public Authentication authenticate(String token) {
        if (StringUtils.hasText(token)) {
            Jwt decodedToken = JwtHelper.decode(token);
            Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                    new TypeReference<Map<String, Object>>() {
                        // Nothing to add here.
                    });

            if (validateToken(token)) {
                return new UsernamePasswordAuthenticationToken(claims.get(ClaimConstants.ISS), null,
                        Collections.emptyList());
            }
        }
        return null;
    }

    private boolean validateToken(String token) {
        boolean result = false;
        try {
            // decode token
            Jwt decodedToken = JwtHelper.decode(token);
            Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                    new TypeReference<Map<String, Object>>() {
                        // Nothing to add here.
                    });

            // verify iss, aud, sub, exp
            assertKnownIssuer(claims);
            assertAudience(claims, issuerURL);
            assertTokenIsCurrent(claims);

            String base64UrlEncodedPublicKey = this.clientPublicKeyProvider.getPublicKey((String)claims.
                    get(ClaimConstants.TENANT_ID),(String)claims.get(ClaimConstants.SUB));
            // base64url decode this public key
            String publicKey = new String(Base64Utils.decodeFromString(base64UrlEncodedPublicKey));

            // verify signature
            SignatureVerifier verifier = getVerifier(publicKey);
            decodedToken.verifySignature(verifier);
        } catch (RuntimeException | PublicKeyNotFoundException e) {
            logger.error(e.getMessage());
            return false;
        }
        return result;
    }

    private void assertKnownIssuer(Map<String, Object> claims) {
        String client = (String) claims.get(ClaimConstants.ISS);
        ClientDetails expectedClient = clientDetailsService.loadClientByClientId(client);
        if (expectedClient == null) {
            throw new InvalidTokenException("Unknown token issuer : " + client);
        }
    }

    private void assertAudience(Map<String, Object> claims, String issuerURL) {
        @SuppressWarnings("unchecked")
        List<String> audience = (List<String>) claims.get(ClaimConstants.AUD);
        
        if (audience.size() != 1 || !audience.get(0).equals(issuerURL)) {
            throw new InvalidTokenException("Audience does not match.");
        }
    }

    private static SignatureVerifier getVerifier(final String signingKey) {
        if (signingKey.startsWith("-----BEGIN PUBLIC KEY-----")) {
            return new RsaVerifier(signingKey);
        }

        throw new IllegalArgumentException(
                "No RSA public key available for token verification.");
    }

    private void assertTokenIsCurrent(final Map<String, Object> claims) {
        Integer expSeconds = (Integer) claims.get(ClaimConstants.EXP);
        long expWithSkewMillis = (expSeconds.longValue() + this.maxAcceptableClockSkewSeconds) * 1000; 
        long currentTime = System.currentTimeMillis();
        
        if ( currentTime > expWithSkewMillis) {
            throw new InvalidTokenException("Token is expired");
        }
    }

}
