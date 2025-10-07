package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OrchestratorZoneConfiguration {

    @Bean
    @ConditionalOnProperty({ "uaa.dashboard.uri" })
    public OrchestratorZoneService orchestratorZoneService(IdentityZoneProvisioning zoneProvisioning,
                                                           @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
                                                           @Qualifier("scimGroupProvisioning") ScimGroupProvisioning groupProvisioning,
                                                           @Qualifier("clientDetailsService") QueryableResourceManager<ClientDetails> clientDetailsService,
                                                           ClientAdminEndpointsValidator clientDetailsValidator,
                                                           @Value("${uaa.url}") String uaaUrl,
                                                           @Value("${uaa.dashboard.uri}") String uaaDashboardUri,
                                                           @Value("${issuer.uri}") String issuerUri) {
        return new OrchestratorZoneService(zoneProvisioning, idpProvisioning, groupProvisioning, clientDetailsService,
                                           clientDetailsValidator, uaaDashboardUri, uaaUrl, issuerUri);
    }

}
