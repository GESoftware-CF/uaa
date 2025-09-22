package org.cloudfoundry.identity.uaa.provider.token;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AbstractTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;

public class JwtBearerAssertionTokenGranter extends AbstractTokenGranter {
    
    public JwtBearerAssertionTokenGranter(AuthorizationServerTokenServices tokenServices,
                                          ClientDetailsService clientDetailsService,
                                             OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE_JWT_BEARER);
    }

}
