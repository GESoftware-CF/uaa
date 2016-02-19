package org.cloudfoundry.identity.uaa.provider.token;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtBearerAssertionAuthenticationFilter extends OncePerRequestFilter {

    private final Log LOGGER = LogFactory.getLog(getClass());
    private static final String RFC_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
 
    private ClientDetailsService clientDetailsService;
    private JwtBearerAssertionPublicKeyProvider publicKeyProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String grantType = request.getParameter("grant_type");

        if (grantType.equals(RFC_JWT_BEARER_GRANT)) {
            String assertion = request.getParameter("assertion");
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (assertion != null) {
                authentication = performClientAuthentication(request, assertion);
                if (authentication != null && authentication.isAuthenticated()) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
    

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setPublicKeyProvider(JwtBearerAssertionPublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
    }

    private Authentication performClientAuthentication(HttpServletRequest request, String assertion) {
        LOGGER.debug("Validate the JWT assertion from the client");
        JwtBearerAssertionTokenAuthenticator tokenAuthenticator = 
                new JwtBearerAssertionTokenAuthenticator(request.getRequestURL().toString());
        tokenAuthenticator.setClientDetailsService(clientDetailsService);
        tokenAuthenticator.setClientPublicKeyProvider(this.publicKeyProvider);
        return tokenAuthenticator.authenticate(assertion);
    }

}
