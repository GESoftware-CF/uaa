package org.cloudfoundry.identity.uaa.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public class ReAuthenticationRequiredFilter extends OncePerRequestFilter {

    static final String REAUTHENTICATION_MARKER_PARAMETER = "uaa_reauth_marker";
    static final String REAUTHENTICATION_MARKER_SESSION_ATTRIBUTE = ReAuthenticationRequiredFilter.class.getName() + ".marker";
    static final String PENDING_AUTHORIZATION_SESSION_ATTRIBUTE = ReAuthenticationRequiredFilter.class.getName() + ".pendingAuthorization";

    private final String samlEntityID;

    public ReAuthenticationRequiredFilter(String samlEntityID) {
        this.samlEntityID = samlEntityID;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HashMap<String, String[]> requestParams = new HashMap<>(request.getParameterMap());
        String marker = request.getParameter(REAUTHENTICATION_MARKER_PARAMETER);
        requestParams.remove(REAUTHENTICATION_MARKER_PARAMETER);

        HttpSession session = request.getSession(false);
        String expectedMarker = session == null ? null
                : (String) session.getAttribute(REAUTHENTICATION_MARKER_SESSION_ATTRIBUTE);
        boolean markerRetry = marker != null && marker.equals(expectedMarker);
        PendingAuthorization pendingAuthorization = session == null ? null
                : (PendingAuthorization) session.getAttribute(PENDING_AUTHORIZATION_SESSION_ATTRIBUTE);
        boolean pendingAuthorizationRequest = isOAuthAuthorizeRequest(request)
                && pendingAuthorization != null && pendingAuthorization.matches(request);
        boolean authenticated = SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication auth
                && auth.isAuthenticated();

        boolean promptLogin = isOAuthAuthorizeRequest(request) && "login".equals(request.getParameter("prompt"));
        boolean reAuthenticationRequired = promptLogin && !markerRetry && !pendingAuthorizationRequest;
        boolean maxAgeExpired = request.getParameter("max_age") != null
            && SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication auth
            && (System.currentTimeMillis() - auth.getAuthenticatedTime()) > (Long.parseLong(request.getParameter("max_age")) * 1000);
        reAuthenticationRequired |= maxAgeExpired;

        if (reAuthenticationRequired) {
            if (session != null) {
                session.invalidate();
            }
            if (maxAgeExpired) {
                requestParams.remove("max_age");
            }
            if (promptLogin) {
                String markerValue = UUID.randomUUID().toString();
                HttpSession newSession = request.getSession(true);
                newSession.setAttribute(REAUTHENTICATION_MARKER_SESSION_ATTRIBUTE, markerValue);
                newSession.setAttribute(PENDING_AUTHORIZATION_SESSION_ATTRIBUTE,
                        PendingAuthorization.from(request));
                requestParams.put(REAUTHENTICATION_MARKER_PARAMETER, new String[] { markerValue });
            }
            sendRedirect(request.getRequestURL().toString(), requestParams, response);
            return;
        }

        if (markerRetry && session != null) {
            session.removeAttribute(REAUTHENTICATION_MARKER_SESSION_ATTRIBUTE);
        }
        if (pendingAuthorizationRequest && authenticated && session != null) {
            session.removeAttribute(PENDING_AUTHORIZATION_SESSION_ATTRIBUTE);
        }

        HttpServletRequest requestWithoutMarker = marker == null ? request : withoutMarker(request, requestParams);
        if (request.getServletPath().startsWith("/saml/SingleLogout/alias/" + samlEntityID)) {
            CsrfFilter.skipRequest(request);
        }
        filterChain.doFilter(requestWithoutMarker, response);
    }

    private boolean isOAuthAuthorizeRequest(HttpServletRequest request) {
        return request.getServletPath().endsWith("/oauth/authorize");
    }

    private HttpServletRequest withoutMarker(HttpServletRequest request, Map<String, String[]> parameters) {
        Map<String, String[]> filteredParameters = new HashMap<>(parameters);
        filteredParameters.remove(REAUTHENTICATION_MARKER_PARAMETER);
        return new HttpServletRequestWrapper(request) {
            @Override
            public String getParameter(String name) {
                return REAUTHENTICATION_MARKER_PARAMETER.equals(name) ? null : super.getParameter(name);
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                return Collections.unmodifiableMap(filteredParameters);
            }

            @Override
            public Enumeration<String> getParameterNames() {
                return Collections.enumeration(filteredParameters.keySet());
            }

            @Override
            public String[] getParameterValues(String name) {
                return filteredParameters.get(name);
            }
        };
    }

    private record PendingAuthorization(String clientId, String redirectUri, String state, String responseType)
            implements java.io.Serializable {

        private static PendingAuthorization from(HttpServletRequest request) {
            return new PendingAuthorization(request.getParameter("client_id"), request.getParameter("redirect_uri"),
                    request.getParameter("state"), request.getParameter("response_type"));
        }

        private boolean matches(HttpServletRequest request) {
            return Objects.equals(clientId, request.getParameter("client_id"))
                    && Objects.equals(redirectUri, request.getParameter("redirect_uri"))
                    && Objects.equals(state, request.getParameter("state"))
                    && Objects.equals(responseType, request.getParameter("response_type"));
        }
    }

    private void sendRedirect(String redirectUrl, Map<String, String[]> params, HttpServletResponse response) throws IOException {
        UriComponentsBuilder builder = UaaUrlUtils.fromUriString(redirectUrl);
        params.forEach(builder::queryParam);
        response.sendRedirect(builder.build().toUriString());
    }
}
