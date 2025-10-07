package org.cloudfoundry.identity.uaa.provider.token;

import java.text.ParseException;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;

public class ClientAssertionHeaderAuthenticator {
    private static final Logger logger = LoggerFactory.getLogger(ClientAssertionHeaderAuthenticator.class);

    private final Integer maxHeaderLifeInSeconds;

    public ClientAssertionHeaderAuthenticator(int maxHeaderLifeInSeconds) {
        this.maxHeaderLifeInSeconds = maxHeaderLifeInSeconds;
    }

    public ClientAssertionHeaderAuthenticator() {
        this(15);
    }

    /**
     * @param clientAssertionHeader  - a JWT with 'iat', 'sub' and 'tenant_id' claims for the client
     * @param proxyPublicKey - RSA public key in PEM format for signature verification
     * @return verified claims in 'clientAssertionHeader' token
     * @throws BadCredentialsException must throw this if authentication fails
     */
    public Map<String, Object> authenticate(final String clientAssertionHeader, final String proxyPublicKey)
            throws BadCredentialsException {
        Jwt clientAssertion = null;
        try {
            if (StringUtils.hasText(clientAssertionHeader)) {
                clientAssertion = JwtHelper.decode(clientAssertionHeader);

                // Use Nimbus JOSE + JWT library to parse PEM key and create verifier
                JWK jwk = JWK.parseFromPEMEncodedObjects(proxyPublicKey);
                RSASSAVerifier verifier = new RSASSAVerifier(jwk.toRSAKey());

                // Since the project's Jwt interface uses verifySignature(Verifier), we need to use
                // a compatible approach. Let's create a custom verifier or use direct verification.
                // For now, let's use the SignedJWT approach directly
                com.nimbusds.jwt.SignedJWT signedJWT = com.nimbusds.jwt.SignedJWT.parse(clientAssertionHeader);

                if (!signedJWT.verify(verifier)) {
                    throw new BadCredentialsException("JWT signature verification failed.");
                }

                Map<String, Object> claims = JsonUtils.readValue(clientAssertion.getClaims(),
                        new TypeReference<Map<String, Object>>() { });

                validateClaims(claims);
                return claims;
            }
        } catch (ParseException | JOSEException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Validation failed for client assertion header. Header:{" + clientAssertion + "}; error: " + e.getMessage(), e);
            }
        } catch (RuntimeException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Validation failed for client assertion header. Header:{" + clientAssertion + "}; error: " + e.getMessage(), e);
            }
        }

        // Do not include error detail in this exception.
        throw new BadCredentialsException("Validation of client assertion header failed.");
    }

    private void validateClaims(Map<String, Object> claims) {
        long currentTime = System.currentTimeMillis();

        //require iat claim and check time skew
        Integer iat = null;
        try {
            iat = (Integer) claims.get(ClaimConstants.IAT);
        } catch (RuntimeException e) {
            throw new BadCredentialsException("iat claim in Predix-Client-Assertion token is in the wrong format.");
        }
        if (iat == null || isSkewed(iat, currentTime) ) {
            throw new BadCredentialsException("iat claim is required in Predix-Client-Assertion token.");
        }

        //force max TTL for header token
        if (currentTime/1000 - iat > this.maxHeaderLifeInSeconds) {
            throw new BadCredentialsException("Predix-Client-Assertion token has expired.");
        }

        //require tenant_id claim
        if (!StringUtils.hasText((String) claims.get(ClaimConstants.TENANT_ID))) {
            throw new BadCredentialsException("tenant_id claim is required in Predix-Client-Assertion token.");
        }

        //require subject claim
        if (!StringUtils.hasText((String) claims.get(ClaimConstants.SUB))) {
            throw new BadCredentialsException("sub claim is required in Predix-Client-Assertion token.");
        }
    }

    private boolean isSkewed(Integer iat, long time) {
        long delta = Math.abs(time/1000 - iat);
        return  delta > 5;
    }

}
