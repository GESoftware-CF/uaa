package org.cloudfoundry.identity.uaa.provider.token;

import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import com.fasterxml.jackson.core.type.TypeReference;

public class JWTBearerAssertionTokenValidator {

    private ClientDetailsService clientDetailsService;
    private JWTBearerAssertionPublicKeyProvider clientPublicKeyProvider;
    private final int maxAcceptableClockSkewSeconds = 60;
    
    private final String issuerURL;
    
    public JWTBearerAssertionTokenValidator(String issuerURL) {
        this.issuerURL = issuerURL;
    }
    
    public Authentication performClientAuthentication(String token) {
        Jwt decodedToken = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                new TypeReference<Map<String, Object>>() {
                    // Nothing to add here.
                });
        if(validateToken(token)) {
            return new UsernamePasswordAuthenticationToken(claims.get(ClaimConstants.ISS), null, Collections.emptyList());
        }
        return null;
    }

    public boolean validateToken(String token) {
        // decode token
        try {
            Jwt decodedToken = JwtHelper.decode(token);
            Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                    new TypeReference<Map<String, Object>>() {
                        // Nothing to add here.
                    });
            // verify iss, aud, sub, exp
            verifyIssuer(claims);
            verifyAudience(claims, issuerURL);
            verifyTimeWindow(claims);

            String publicKey = this.clientPublicKeyProvider.getPublicKey(claims);

            // verify signature
            SignatureVerifier verifier = getVerifier(publicKey);
            decodedToken.verifySignature(verifier);
        } catch (RuntimeException e) {
            return false;
        }
        return true;
    }
    
    public void setClientPublicKeyProvider(JWTBearerAssertionPublicKeyProvider clientPublicKeyProvider) {
        this.clientPublicKeyProvider = clientPublicKeyProvider;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    private void verifyIssuer(Map<String, Object> claims) {
        String client = (String) claims.get(ClaimConstants.ISS);
        ClientDetails expectedClient = clientDetailsService.loadClientByClientId(client);
        if (expectedClient == null) {
            throw new InvalidTokenException("Invalid client.");
        }
    }

    private void verifyAudience(Map<String, Object> claims, String issuerURL) {
        List<String> audience = (List<String>) claims.get(ClaimConstants.AUD);
        
        if (audience.size() != 1 || !audience.get(0).equals(issuerURL)) {
            throw new InvalidTokenException("Audience does not match.");
        }
    }

    private static SignatureVerifier getVerifier(final String signingKey) {
        if (isAssymetricKey(signingKey)) {
            return new RsaVerifier(signingKey);
        }

        throw new IllegalArgumentException(
                "Unsupported key detected. FastRemoteTokenService only supports RSA public keys for token verification.");
    }

    private static boolean isAssymetricKey(final String key) {
        return key.startsWith("-----BEGIN PUBLIC KEY-----");
    }

    private void verifyTimeWindow(final Map<String, Object> claims) {
        Date expDate = getExpDate(claims);
        Date currentDate = new Date();

        if (expDate != null && expDate.before(currentDate)) {
            throw new InvalidTokenException("Token is expired");
        }
    }

    protected Date getExpDate(final Map<String, Object> claims) {
        Integer exp = (Integer) claims.get(ClaimConstants.EXP);
        return new Date((exp.longValue() + this.maxAcceptableClockSkewSeconds) * 1000l);
    }
}
