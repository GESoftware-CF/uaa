package org.cloudfoundry.identity.uaa.provider.token;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.OauthGrant;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;
import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;

public class JwtBearerAssertionAuthenticationFilter extends OncePerRequestFilter {

    private final Log LOGGER = LogFactory.getLog(getClass());
 
    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider publicKeyProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String grantType = request.getParameter("grant_type");

        if (grantType.equals(OauthGrant.JWT_BEARER)) {
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

    public void setPublicKeyProvider(DevicePublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
    }

    private Authentication performClientAuthentication(HttpServletRequest request, String assertion) {
        LOGGER.debug("Validating JWT assertion from the client");
        JwtBearerAssertionTokenAuthenticator tokenAuthenticator = 
                new JwtBearerAssertionTokenAuthenticator(request.getRequestURL().toString());
        tokenAuthenticator.setClientDetailsService(clientDetailsService);
        tokenAuthenticator.setClientPublicKeyProvider(this.publicKeyProvider);
        return tokenAuthenticator.authenticate(assertion);
    }

}
