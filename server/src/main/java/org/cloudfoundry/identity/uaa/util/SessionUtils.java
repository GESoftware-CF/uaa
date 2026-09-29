package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.SavedRequest;

import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.time.Duration;
import java.util.UUID;
import org.springframework.web.util.UriComponentsBuilder;

public final class SessionUtils {
    public static final String PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED";
    public static final String FORCE_PASSWORD_EXPIRED_USER = "FORCE_PASSWORD_EXPIRED_USER";
    public static final String FORCE_IDP_REAUTHENTICATION = "FORCE_IDP_REAUTHENTICATION";
    public static final String IDP_REAUTHENTICATION_PARAMETER = "_uaa_reauth";
    public static final String OIDC_PROMPT_PARAMETER = "oidc_prompt";
    public static final String SAML_PROMPT_PARAMETER = "saml_prompt";
    private static final long IDP_REAUTHENTICATION_TIMEOUT = Duration.ofMinutes(5).toMillis();

    // shadows org.springframework.security.web.savedrequest.HttpSessionRequestCache.SAVED_REQUEST
    //         org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache.DEFAULT_SAVED_REQUEST_ATTR
    //
    public static final String SAVED_REQUEST_SESSION_ATTRIBUTE = "SPRING_SECURITY_SAVED_REQUEST";

    // shadows org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY
    //         org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository.DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME
    //         org.springframework.session.jdbc.JdbcIndexedSessionRepository.SPRING_SECURITY_CONTEXT
    //         org.springframework.session.PrincipalNameIndexResolver.SPRING_SECURITY_CONTEXT
    //         org.springframework.session.security.SpringSessionBackedSessionInformation.SPRING_SECURITY_CONTEXT
    public static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

    private static final String EXTERNAL_OAUTH_STATE_ATTRIBUTE_PREFIX = "external-oauth-state-";
    private static final String EXTERNAL_OAUTH_CODE_VERIFIER_ATTRIBUTE_PREFIX = "external-oauth-verifier-";

    private SessionUtils() {
    }

    public static String startIdpReauthentication(HttpSession session, String authorizationUrl,
            boolean oidcLogin, boolean samlLogin) {
        String continuationUrl = UriComponentsBuilder.fromUriString(authorizationUrl)
                .replaceQueryParam(IDP_REAUTHENTICATION_PARAMETER, UUID.randomUUID().toString())
                .build().toUriString();
        session.setAttribute(FORCE_IDP_REAUTHENTICATION, new IdpReauthentication(
                continuationUrl, System.currentTimeMillis() + IDP_REAUTHENTICATION_TIMEOUT,
                oidcLogin, samlLogin));
        return continuationUrl;
    }

    public static boolean isOidcReauthentication(HttpSession session) {
        IdpReauthentication pending = getIdpReauthentication(session);
        return pending != null && pending.oidcLogin();
    }

    public static boolean isSamlReauthentication(HttpSession session) {
        IdpReauthentication pending = getIdpReauthentication(session);
        return pending != null && pending.samlLogin();
    }

    public static boolean isForceIdpReauthentication(HttpSession session) {
        return getIdpReauthentication(session) != null;
    }

    private static IdpReauthentication getIdpReauthentication(HttpSession session) {
        SavedRequest savedRequest = session == null ? null : getSavedRequestSession(session);
        return savedRequest == null ? null
                : getIdpReauthentication(session, savedRequest.getRedirectUrl());
    }

    public static boolean isForceIdpReauthentication(HttpSession session, String authorizationUrl) {
        return getIdpReauthentication(session, authorizationUrl) != null;
    }

    private static IdpReauthentication getIdpReauthentication(HttpSession session, String authorizationUrl) {
        if (session == null
                || !(session.getAttribute(FORCE_IDP_REAUTHENTICATION) instanceof IdpReauthentication pending)) {
            return null;
        }
        if (System.currentTimeMillis() >= pending.expiresAt()) {
            clearForceIdpReauthentication(session);
            return null;
        }
        return pending.authorizationUrl().equals(authorizationUrl) ? pending : null;
    }

    public static void clearForceIdpReauthentication(HttpSession session) {
        if (session != null) {
            session.removeAttribute(FORCE_IDP_REAUTHENTICATION);
        }
    }

    private record IdpReauthentication(String authorizationUrl, long expiresAt,
            boolean oidcLogin, boolean samlLogin)
    implements Serializable {
    }

    public static boolean isPasswordChangeRequired(HttpSession session) {
        Object passwordChangeRequired = session.getAttribute(PASSWORD_CHANGE_REQUIRED);

        if (passwordChangeRequired == null) {
            return false;
        }

        if (!(passwordChangeRequired instanceof Boolean)) {
            throw new IllegalArgumentException("The %s attribute on the session must be a Boolean".formatted(PASSWORD_CHANGE_REQUIRED));
        }

        return (Boolean) passwordChangeRequired;
    }

    public static void setPasswordChangeRequired(HttpSession session, boolean passwordChangeRequired) {
        session.setAttribute(PASSWORD_CHANGE_REQUIRED, passwordChangeRequired);
    }

    public static void setForcePasswordExpiredUser(HttpSession session, UaaAuthentication uaaAuthentication) {
        session.setAttribute(FORCE_PASSWORD_EXPIRED_USER, uaaAuthentication);
    }

    public static UaaAuthentication getForcePasswordExpiredUser(HttpSession session) {
        return (UaaAuthentication) session.getAttribute(FORCE_PASSWORD_EXPIRED_USER);
    }

    public static void setStateParam(HttpSession session, String stateParamKey, String state) {
        session.setAttribute(stateParamKey, state);
    }

    public static Object getStateParam(HttpSession session, String stateParamKey) {
        return session.getAttribute(stateParamKey);
    }

    public static void setSecurityContext(HttpSession session, SecurityContext context) {
        session.setAttribute(SPRING_SECURITY_CONTEXT, context);
    }

    public static void setSavedRequestSession(HttpSession session, SavedRequest clientRedirectSavedRequest) {
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, clientRedirectSavedRequest);
    }

    public static SavedRequest getSavedRequestSession(HttpSession session) {
        return (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
    }

    public static AuthenticationException getAuthenticationException(HttpSession session) {
        return (AuthenticationException) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

    public static String stateParameterAttributeKeyForIdp(String idpOriginKey) {
        return EXTERNAL_OAUTH_STATE_ATTRIBUTE_PREFIX + idpOriginKey;
    }

    public static String codeVerifierParameterAttributeKeyForIdp(String idpOriginKey) {
        return EXTERNAL_OAUTH_CODE_VERIFIER_ATTRIBUTE_PREFIX + idpOriginKey;
    }
}
