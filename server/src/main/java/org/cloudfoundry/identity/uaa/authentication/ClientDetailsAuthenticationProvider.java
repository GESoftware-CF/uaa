/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthConfigurationReader;
import org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthSubjectMatcher;
import org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_EMPTY;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_PRIVATE_KEY_JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_TLS_CLIENT_AUTH;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getSafeParameterValue;

public class ClientDetailsAuthenticationProvider extends DaoAuthenticationProvider {


    private final JwtClientAuthentication jwtClientAuthentication;
    private final Map<String, Set<String>> legacyNoSecretAllowedZoneClientIds;
    private final TlsClientAuthentication tlsClientAuthentication;

    public ClientDetailsAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder encoder, JwtClientAuthentication jwtClientAuthentication) {
        this(userDetailsService, encoder, jwtClientAuthentication, Collections.emptyMap(), null);
    }

    public ClientDetailsAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder encoder, JwtClientAuthentication jwtClientAuthentication, Map<String, Set<String>> legacyNoSecretAllowedZoneClientIds) {
        this(userDetailsService, encoder, jwtClientAuthentication, legacyNoSecretAllowedZoneClientIds, null);
    }

    public ClientDetailsAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder encoder,
            JwtClientAuthentication jwtClientAuthentication, TlsClientAuthentication tlsClientAuthentication) {
        this(userDetailsService, encoder, jwtClientAuthentication, Collections.emptyMap(), tlsClientAuthentication);
    }

    public ClientDetailsAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder encoder,
            JwtClientAuthentication jwtClientAuthentication, Map<String, Set<String>> legacyNoSecretAllowedZoneClientIds,
            TlsClientAuthentication tlsClientAuthentication) {
        super();
        setUserDetailsService(userDetailsService);
        setPasswordEncoder(encoder);
        this.jwtClientAuthentication = jwtClientAuthentication;
        this.legacyNoSecretAllowedZoneClientIds = legacyNoSecretAllowedZoneClientIds != null ? legacyNoSecretAllowedZoneClientIds : Collections.emptyMap();
        this.tlsClientAuthentication = tlsClientAuthentication;
    }


    /**
     * Parses zone-to-client mapping from environment variable.
     * Format: "zone1:client1,zone1:client2,zone2:client3"
     * This allows multiple clients per zone.
     *
     * @param commaSeparatedZoneClientMapping comma-separated zone:clientId pairs
     * @return Map of zone IDs to Set of allowed client IDs
     */
    public static Map<String, Set<String>> parseZoneClientIdMapping(String commaSeparatedZoneClientMapping) {
        if (commaSeparatedZoneClientMapping == null || commaSeparatedZoneClientMapping.isBlank()) {
            return Collections.emptyMap();
        }
        Map<String, Set<String>> mapping = new HashMap<>();
        Arrays.stream(commaSeparatedZoneClientMapping.split(","))
                .map(String::trim)
                .filter(s -> s.contains(":"))
                .forEach(entry -> {
                    String[] parts = entry.split(":", 2);
                    String zoneId = parts[0].trim();
                    String clientId = parts[1].trim();
                    if (!zoneId.isEmpty() && !clientId.isEmpty()) {
                        mapping.computeIfAbsent(zoneId, k -> new java.util.HashSet<>()).add(clientId);
                    }
                });
        return mapping;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {


        String[] passwordList;
        String password = userDetails.getPassword();
        if (password != null) {
            passwordList = password.split(" ");
        } else {
            passwordList = new String[]{password};
        }

        AuthenticationException error = null;
        for (String pwd : passwordList) {
            try {
                UaaClient uaaClient = new UaaClient(userDetails, pwd);
                TlsClientAuthConfiguration tlsClientAuthConfiguration = getTlsClientAuthConfiguration(uaaClient);
                boolean tlsClientAuthConfigured = TlsClientAuthConfiguration.isConfigured(tlsClientAuthConfiguration);
                Map<String, Object> info = uaaClient.getAdditionalInformation();
                Boolean boundAccessTokens = TlsClientAuthConfiguration.parseBoundAccessTokens(info == null ? null
                        : info.get(TlsClientAuthConfiguration.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS));
                if (!tlsClientAuthConfigured && !Boolean.FALSE.equals(boundAccessTokens)) {
                    throw new BadCredentialsException(
                            TlsClientAuthConfiguration.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS
                                    + " requires a client configured for tls_client_auth");
                }
                if (tlsClientAuthConfigured && boundAccessTokens == null) {
                    throw new BadCredentialsException("tls_client_auth: the client's "
                            + TlsClientAuthConfiguration.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS + " cannot be read");
                }
                if (isTlsClientAuthPath(authentication.getDetails()) && !tlsClientAuthConfigured) {
                    error = new BadCredentialsException(
                            "tls_client_auth: /oauth/mtls/token requires a client configured with tls-client-auth-ca");
                    break;
                }
                if (tlsClientAuthConfigured) {
                    if (presentsClientCredentials(authentication) || !isTlsClientAuthPath(authentication.getDetails())) {
                        error = new BadCredentialsException(
                                "tls_client_auth: configured clients must authenticate at /oauth/mtls/token without client credentials");
                    } else if (tlsClientAuthConfiguration.configuredSubjectBindings().size() != 1) {
                        error = new BadCredentialsException(
                                "tls_client_auth: client must register exactly one certificate subject value. Configure one of "
                                        + String.join(", ", TlsClientAuthConfiguration.SUBJECT_BINDING_PARAMETERS));
                    } else {
                        setAuthenticationMethod(authentication, CLIENT_AUTH_TLS_CLIENT_AUTH);
                        if (!validateTlsClientAuth(tlsClientAuthConfiguration)) {
                            error = new BadCredentialsException("tls_client_auth: certificate validation failed");
                        }
                    }
                    break;
                }
                if (ObjectUtils.isEmpty(authentication.getCredentials())) {
                    if (isPublicGrantTypeUsageAllowed(authentication.getDetails()) && uaaClient.isAllowPublic()) {
                        // in case of grant_type=authorization_code and code_verifier passed (PKCE) we check if client has option allowpublic with true and continue even if no secret is in request
                        setAuthenticationMethod(authentication, CLIENT_AUTH_NONE);
                        break;
                    } else if (isPrivateKeyJwt(authentication.getDetails())) {
                        setAuthenticationMethod(authentication, CLIENT_AUTH_PRIVATE_KEY_JWT);
                        if (!validatePrivateKeyJwt(authentication.getDetails(), uaaClient)) {
                            error = new BadCredentialsException("Bad client_assertion type");
                        }
                        break;
                    } else if (isLegacyNoSecretFlowAllowed(authentication.getDetails(), legacyNoSecretAllowedZoneClientIds)) {
                        // Allow legacy clients without secrets for password grant type only for whitelisted zone IDs and client IDs
                        // Additional security: restricts to specific client IDs per zone
                        setAuthenticationMethod(authentication, CLIENT_AUTH_EMPTY);
                        break;
                    } else {
                        // set internally empty as client_auth_method e.g. cf client
                        setAuthenticationMethod(authentication, CLIENT_AUTH_EMPTY);
                    }
                }
                if (uaaClient.getPassword() == null) {
                    error = new BadCredentialsException("Missing credentials");
                    break;
                }
                super.additionalAuthenticationChecks(uaaClient, authentication);
                error = null;
                break;
            } catch (AuthenticationException e) {
                error = e;
            }
        }
        if (error != null) {
            throw error;
        }
    }

    private static void setAuthenticationMethod(AbstractAuthenticationToken authentication, String method) {
        if (authentication.getDetails() instanceof  UaaAuthenticationDetails) {
            ((UaaAuthenticationDetails) authentication.getDetails()).setAuthenticationMethod(method);
        }
    }

    private static boolean isPublicGrantTypeUsageAllowed(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails authenticationDetails = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = getRequestParameters(authenticationDetails);
        // allowPublic is intended for authorization_code with PKCE, refresh_token, and password grants
        // client_credentials is handled separately via isLegacyNoSecretFlowAllowed for backward compatibility
        return isPublicTokenRequest(authenticationDetails) && (isAuthorizationWithPkce(requestParameters) || isRefreshFlow(requestParameters) || isPasswordFlow(requestParameters));
    }

    private static boolean isPasswordFlow(Map<String, String[]> requestParameters) {
        // Note: username and password are filtered from parameterMap in UaaAuthenticationDetails,
        // so we only check for client_id and grant_type=password
        return StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id")))
                && TokenConstants.GRANT_TYPE_PASSWORD.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private boolean isLegacyNoSecretFlowAllowed(Object uaaAuthenticationDetails, Map<String, Set<String>> allowedZoneClientIds) {
        String currentZoneId = IdentityZoneHolder.getCurrentZoneId();
        UaaAuthenticationDetails authenticationDetails = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = getRequestParameters(authenticationDetails);

        // Check request path is /oauth/token (regardless of Authorization header presence)
        // Legacy clients may send Basic auth with empty password: Authorization: Basic base64(clientId:)
        if (!isTokenEndpoint(authenticationDetails)) {
            return false;
        }

        if (!isPasswordGrantType(requestParameters)) {
            return false;
        }

        // Resolve client_id: from request parameter or from UaaAuthenticationDetails
        // When client sends Basic auth header, client_id may not be in the form parameters
        // but is available in UaaAuthenticationDetails.getClientId()
        String requestClientId = getSafeParameterValue(requestParameters.get("client_id"));
        if (!StringUtils.hasText(requestClientId)) {
            requestClientId = authenticationDetails.getClientId();
        }

        // Check if both zone and client ID are whitelisted
        // Legacy support: only password grant is allowed without client secret
        // Password grant validates user credentials, so client secret is optional for backward compatibility
        // This is restricted to whitelisted zone + client ID pairs for security
        boolean zoneWhitelisted = allowedZoneClientIds.containsKey(currentZoneId);
        boolean clientWhitelisted = zoneWhitelisted && allowedZoneClientIds.get(currentZoneId).contains(requestClientId);
        return clientWhitelisted;
    }

    private static boolean isTokenEndpoint(UaaAuthenticationDetails authenticationDetails) {
        return "/oauth/token".equals(authenticationDetails.getRequestPath());
    }

    private static boolean isPasswordGrantType(Map<String, String[]> requestParameters) {
        return TokenConstants.GRANT_TYPE_PASSWORD.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private static boolean isPublicTokenRequest(UaaAuthenticationDetails authenticationDetails) {
        if (authenticationDetails.isAuthorizationSet()) {
            return false;
        }
        String path = authenticationDetails.getRequestPath();
        return "/oauth/token".equals(path) || (path != null && path.startsWith("/oauth/token/alias/"));
    }

    private static boolean isAuthorizationWithPkce(Map<String, String[]> requestParameters) {
        return PkceValidationService.isCodeVerifierParameterValid(getSafeParameterValue(requestParameters.get("code_verifier"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("code"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("redirect_uri"))) &&
                TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private static boolean isRefreshFlow(Map<String, String[]> requestParameters) {
        return StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id")))
                && StringUtils.hasText(getSafeParameterValue(requestParameters.get("refresh_token")))
                && TokenConstants.GRANT_TYPE_REFRESH_TOKEN.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private static UaaAuthenticationDetails getUaaAuthenticationDetails(Object object) {
        return object instanceof UaaAuthenticationDetails uad ? uad : new UaaAuthenticationDetails();
    }

    private static Map<String, String[]> getRequestParameters(UaaAuthenticationDetails authenticationDetails) {
        return Optional.ofNullable(authenticationDetails.getParameterMap()).orElse(Collections.emptyMap());
    }

    private static boolean isPrivateKeyJwt(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails authenticationDetails = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = getRequestParameters(authenticationDetails);
        return isPublicTokenRequest(authenticationDetails) &&
                !StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_secret"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_assertion_type"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_assertion")));
    }

    private boolean validatePrivateKeyJwt(Object uaaAuthenticationDetails, UaaClient uaaClient) {
        return jwtClientAuthentication.validateClientJwt(getRequestParameters(getUaaAuthenticationDetails(uaaAuthenticationDetails)),
                uaaClient.getClientJwtConfiguration(), uaaClient.getUsername());
    }

    static boolean isTlsClientAuthPath(Object authenticationDetails) {
        UaaAuthenticationDetails details = getUaaAuthenticationDetails(authenticationDetails);
        return RawPeerCertificateCaptureFilter.isMtlsTokenPath(details.getServletPath())
                || RawPeerCertificateCaptureFilter.isMtlsTokenPath(details.getRequestPath());
    }

    private static boolean presentsClientCredentials(UsernamePasswordAuthenticationToken authentication) {
        if (!ObjectUtils.isEmpty(authentication.getCredentials())) {
            return true;
        }
        if (!(authentication.getDetails() instanceof UaaAuthenticationDetails details)) {
            return false;
        }
        Map<String, String[]> parameters = getRequestParameters(details);
        return details.isAuthorizationSet() || List.of("client_secret", "client_assertion", "client_assertion_type")
                .stream().anyMatch(parameters::containsKey);
    }

    boolean validateTlsClientAuth(TlsClientAuthConfiguration config) {
        if (!tlsClientAuthentication.hasCertificateFromRequest()) {
            return false;
        }
        try {
            X509Certificate[] chain = tlsClientAuthentication.getCertificateChainFromRequest(config);
            return chain != null && chain.length > 0
                    && tlsClientAuthentication.validateClientCert(chain, config).isPresent()
                    && TlsClientAuthSubjectMatcher.matches(chain[0], config)
                    && tlsClientAuthentication.certificateSatisfiesRequiredClaims(chain[0], config);
        } catch (InvalidClientDetailsException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    static TlsClientAuthConfiguration getTlsClientAuthConfiguration(UaaClient client) {
        Map<String, Object> info = client.getAdditionalInformation();
        if (info == null) {
            return null;
        }
        Object rawCa = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
        Object rawCaReference = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF);
        if (rawCa instanceof String || rawCaReference instanceof String) {
            try {
                return TlsClientAuthConfigurationReader.read(info);
            } catch (IllegalArgumentException e) {
                throw new BadCredentialsException("tls_client_auth: client configuration cannot be read", e);
            }
        }
        if (TlsClientAuthConfiguration.CERTIFICATE_ONLY_SETTING_KEYS.stream().anyMatch(key -> info.get(key) != null)
                || TlsClientAuthConfiguration.PROXY_TRUST_KEYS.stream().anyMatch(info::containsKey)) {
            throw new BadCredentialsException("tls_client_auth: certificate settings require a trusted CA");
        }
        return null;
    }
}
