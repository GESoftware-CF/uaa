package org.cloudfoundry.identity.uaa.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ReAuthenticationRequiredFilter extends OncePerRequestFilter {

    private final String samlEntityID;

    public ReAuthenticationRequiredFilter(String samlEntityID) {
        this.samlEntityID = samlEntityID;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        boolean reAuthenticationRequired = false;
        boolean authorizationRequest = request.getRequestURI()
                .equals(request.getContextPath() + "/oauth/authorize");
        boolean oidcLogin = authorizationRequest
        && "login".equals(request.getParameter(SessionUtils.OIDC_PROMPT_PARAMETER));
        boolean samlLogin = authorizationRequest
        && "login".equals(request.getParameter(SessionUtils.SAML_PROMPT_PARAMETER));
        HashMap<String, String[]> requestParams = new HashMap<>(request.getParameterMap());
        if ("login".equals(request.getParameter("prompt"))) {
            reAuthenticationRequired = true;
            requestParams.remove("prompt");
        }
        if (oidcLogin || samlLogin) {
            reAuthenticationRequired = true;
            requestParams.remove(SessionUtils.OIDC_PROMPT_PARAMETER);
            requestParams.remove(SessionUtils.SAML_PROMPT_PARAMETER);
        }
        if (request.getParameter("max_age") != null
            && SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication auth
            && (System.currentTimeMillis() - auth.getAuthenticatedTime()) > (Long.parseLong(request.getParameter("max_age")) * 1000))
        {
                reAuthenticationRequired = true;
                requestParams.remove("max_age");
        }
        if (reAuthenticationRequired) {
            request.getSession().invalidate();
            String redirectUrl = buildRedirectUrl(request.getRequestURL().toString(), requestParams);
            if (oidcLogin || samlLogin) {
                // Otherwise the repository saves the still-authenticated context into the new session.
                SecurityContextHolder.clearContext();
                redirectUrl = SessionUtils.startIdpReauthentication(
                        request.getSession(true), redirectUrl, oidcLogin, samlLogin);
            }
            response.sendRedirect(redirectUrl);
        } else {
            if (authorizationRequest) {
                var authentication = SecurityContextHolder.getContext().getAuthentication();
                boolean authenticated = authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
                if (authenticated || !SessionUtils.isForceIdpReauthentication(
                        request.getSession(false), UrlUtils.buildFullRequestUrl(request))) {
                    SessionUtils.clearForceIdpReauthentication(request.getSession(false));
                }
            }
            if (request.getServletPath().startsWith("/saml/SingleLogout/alias/" + samlEntityID)) {
                CsrfFilter.skipRequest(request);
            }
            filterChain.doFilter(request, response);
        }
    }

    private String buildRedirectUrl(String redirectUrl, Map<String, String[]> params) {
        UriComponentsBuilder builder = UaaUrlUtils.fromUriString(redirectUrl);
        params.forEach(builder::queryParam);
        return builder.build().toUriString();
    }
}
