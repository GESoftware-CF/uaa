package org.cloudfoundry.identity.uaa.provider.token;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtBearerAuthenticationFilter extends OncePerRequestFilter {

    private final Log LOGGER = LogFactory.getLog(getClass());
    private AuthenticationManager authenticationManager;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = 
            new WebAuthenticationDetailsSource();
    
    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public JwtBearerAuthenticationFilter(AuthenticationManager authNManager) {
        this.authenticationManager = authNManager;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        LOGGER.debug("JwtBearerAuthentication filter invoked");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //TODO: Check for jwt-beare grant_type, instead of assertion? 
        String assertion = request.getParameter("assertion");
        if ((authentication == null || !authentication.isAuthenticated()) && assertion != null) {
            authentication = performClientAuthentication(request);
            if (authentication != null && authentication.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        
        filterChain.doFilter(request, response);
    }

    //FIXME: Test implementation - Change this to use JwtBearerTokenValidator
    private Authentication performClientAuthentication(HttpServletRequest request) {
        Authentication authentication;
        LOGGER.debug("Validate the JWT assertion from the client");
        
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("admin",
                "adminsecret");
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
        authentication = this.authenticationManager.authenticate(authRequest);
        return authentication;
    }

}
