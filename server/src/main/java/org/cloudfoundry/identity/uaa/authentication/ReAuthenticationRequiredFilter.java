package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ReAuthenticationRequiredFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        boolean reAuthenticationRequired = false;
        logger.info("MARCH9DEBUG: ReAuthenticationRequiredFilter -> doFilterInternal request session is: " + request.getSession(false).getId());
        logger.info("MARCH9DEBUG: ReAuthenticationRequiredFilter -> doFilterInternal request prompt is: " + request.getParameter("prompt"));
        logger.info("MARCH9DEBUG: ReAuthenticationRequiredFilter -> doFilterInternal request max_age is: " + request.getParameter("max_age"));
        HashMap<String, String[]> requestParams = new HashMap<>(request.getParameterMap());
        if ("login".equals(request.getParameter("prompt"))) {
            reAuthenticationRequired = true;
            requestParams.remove("prompt");
        }
        if (request.getParameter("max_age") != null && SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication) {
            UaaAuthentication auth = (UaaAuthentication) SecurityContextHolder.getContext().getAuthentication();
            if ((System.currentTimeMillis() - auth.getAuthenticatedTime()) > (Long.valueOf(request.getParameter("max_age"))*1000)) {
                reAuthenticationRequired = true;
                requestParams.remove("max_age");
            }
        }
        if (reAuthenticationRequired) {
            logger.info("MARCH9DEBUG: ReAuthenticationRequiredFilter -> doFilterInternal -> session invalidated" + request.getSession(false).getId());
            request.getSession().invalidate();
            sendRedirect(request.getRequestURL().toString(), requestParams, request, response);
        } else {
            logger.info("MARCH9DEBUG: ReAuthenticationRequiredFilter -> doFilterInternal -> reauth not required for session ID: " + request.getSession(false).getId());
            filterChain.doFilter(request, response);
        }
    }

    protected void sendRedirect(String redirectUrl, Map<String, String[]> params, HttpServletRequest request, HttpServletResponse response) throws IOException {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUrl);
        for (String key : params.keySet()) {
            builder.queryParam(key, params.get(key));
        }
        response.sendRedirect(builder.build().toUriString());
    }
}
