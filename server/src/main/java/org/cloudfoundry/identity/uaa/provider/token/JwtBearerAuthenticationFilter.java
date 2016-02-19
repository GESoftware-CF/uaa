package org.cloudfoundry.identity.uaa.provider.token;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtBearerAuthenticationFilter extends OncePerRequestFilter {

    private final Log LOGGER = LogFactory.getLog(getClass());
 
    private ClientDetailsService clientDetailsService;

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = 
            new WebAuthenticationDetailsSource();
    
    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }
    
    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        Assert.notNull(clientDetailsService, "ClientDetailsService required");
        this.clientDetailsService = clientDetailsService;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        LOGGER.debug("JwtBearerAuthentication filter invoked");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //TODO: Check for jwt-bearer grant_type, instead of assertion? 
        String assertion = request.getParameter("assertion");
        if ((authentication == null || !authentication.isAuthenticated()) && assertion != null) {
            authentication = performClientAuthentication(request, assertion);
            if (authentication != null && authentication.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        
        filterChain.doFilter(request, response);
    }

    //FIXME: Test implementation - Change this to use JwtBearerTokenValidator
    private Authentication performClientAuthentication(HttpServletRequest request, String assertion) {
        LOGGER.debug("Validate the JWT assertion from the client");
        JWTBearerAssertionTokenValidator tokenValidator = new JWTBearerAssertionTokenValidator(getIssuerUrl(request));
        tokenValidator.setClientDetailsService(clientDetailsService);
        tokenValidator.setClientPublicKeyProvider(new MockGEPublicKeyProvider());
        return tokenValidator.performClientAuthentication(assertion);
    }


    private String getIssuerUrl(HttpServletRequest request) {
        return "https://zone1.uaa.ge.com/oauth/token";
    }
}
