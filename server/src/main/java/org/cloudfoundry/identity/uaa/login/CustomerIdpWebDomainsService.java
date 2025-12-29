package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Service for managing customer identity provider web domains configuration.
 * This service determines which identity providers should be displayed with
 * the "Or sign in with:" separator on the login page.
 * 
 * Can be accessed directly in templates via: @customerIdpService
 */
@Service("customerIdpService")
public class CustomerIdpWebDomainsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomerIdpWebDomainsService.class);

    private final List<String> customerIdpWebDomains;

    public CustomerIdpWebDomainsService(
            @Value("${customer_idp.web_domains:}") List<String> customerIdpWebDomains) {
        this.customerIdpWebDomains = customerIdpWebDomains != null ? customerIdpWebDomains : Collections.emptyList();
        logger.info("CustomerIdpWebDomainsService initialized with {} domains", this.customerIdpWebDomains.size());
        logger.debug("Customer IDP web domains configured: {}", this.customerIdpWebDomains);
    }

    /**
     * Gets the configured customer IDP web domains.
     *
     * @return List of customer IDP web domains
     */
    public List<String> getCustomerIdpWebDomains() {
        logger.debug("getCustomerIdpWebDomains() called, returning {} domains", customerIdpWebDomains.size());
        return customerIdpWebDomains;
    }

    /**
     * Checks if there are any customer IDPs configured.
     *
     * @return true if customer IDP web domains are configured
     */
    public boolean hasCustomerIdpWebDomains() {
        boolean hasCustomerIdps = customerIdpWebDomains != null && !customerIdpWebDomains.isEmpty();
        logger.debug("hasCustomerIdpWebDomains() called, returning: {}", hasCustomerIdps);
        return hasCustomerIdps;
    }

    /**
     * Determines if there are customer SAML identity providers that should be displayed
     * with the "Or sign in with:" separator.
     *
     * @param samlIdentityProviders Map of SAML identity providers
     * @return true if there are customer SAML IDPs to display
     */
    public boolean hasCustomerSamlIdps(Map<String, SamlIdentityProviderDefinition> samlIdentityProviders) {
        logger.debug("hasCustomerSamlIdps() called with {} SAML providers", 
                     samlIdentityProviders != null ? samlIdentityProviders.size() : 0);
        
        if (!hasCustomerIdpWebDomains() || samlIdentityProviders == null || samlIdentityProviders.isEmpty()) {
            logger.debug("No customer SAML IDPs: hasCustomerIdpWebDomains={}, samlProviders={}", 
                         hasCustomerIdpWebDomains(), samlIdentityProviders != null ? "not null" : "null");
            return false;
        }

        boolean result = samlIdentityProviders.values().stream().anyMatch(idp ->
                idp.isShowSamlLink() &&
                customerIdpWebDomains.stream().anyMatch(domain -> !idp.getMetaDataLocation().contains(domain))
        );
        logger.debug("hasCustomerSamlIdps() returning: {}", result);
        return result;
    }

    /**
     * Determines if there are customer OAuth links that should be displayed
     * with the "Or sign in with:" separator.
     *
     * @param oauthLinks Map of OAuth authentication URLs to link text
     * @return true if there are customer OAuth links to display
     */
    public boolean hasCustomerOAuthLinks(Map<String, String> oauthLinks) {
        logger.debug("hasCustomerOAuthLinks() called with {} OAuth links", 
                     oauthLinks != null ? oauthLinks.size() : 0);
        
        if (!hasCustomerIdpWebDomains() || oauthLinks == null || oauthLinks.isEmpty()) {
            logger.debug("No customer OAuth links: hasCustomerIdpWebDomains={}, oauthLinks={}", 
                         hasCustomerIdpWebDomains(), oauthLinks != null ? "not null" : "null");
            return false;
        }

        boolean result = oauthLinks.values().stream().anyMatch(linkText ->
                customerIdpWebDomains.stream().anyMatch(domain -> !linkText.contains(domain))
        );
        logger.debug("hasCustomerOAuthLinks() returning: {}", result);
        return result;
    }

    /**
     * Checks if a given metadata location or link text is NOT a customer IDP.
     * This is useful for determining whether to show the "Or sign in with:" separator.
     *
     * @param metadataOrLinkText The metadata location or link text to check
     * @return true if this is not a customer IDP (i.e., should be displayed with separator)
     */
    public boolean isNotCustomerIdp(String metadataOrLinkText) {
        if (!hasCustomerIdpWebDomains() || metadataOrLinkText == null) {
            return true;
        }

        return customerIdpWebDomains.stream().noneMatch(metadataOrLinkText::contains);
    }

    /**
     * Enriches the login page model with customer IDP information.
     * This method adds the necessary attributes for the login.html template.
     *
     * @param samlIdentityProviders Map of SAML identity providers
     * @param oauthIdentityProviders Map of OAuth identity providers  
     * @return LoginPageIdpInfo containing IDP information for the view
     */
    public LoginPageIdpInfo prepareLoginPageIdpInfo(
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdentityProviders) {
        
        LoginPageIdpInfo info = new LoginPageIdpInfo();
        info.setCustomerIdpWebDomains(customerIdpWebDomains);
        info.setHasCustomerSamlIdps(hasCustomerSamlIdps(samlIdentityProviders));
        
        // For OAuth links, we need to check if there are any non-customer OAuth providers
        // This will be calculated when OAuth links are created
        info.setHasCustomerOAuthIdps(false); // Will be updated by the endpoint
        
        return info;
    }

    /**
     * DTO class to hold IDP information for the login page.
     */
    public static class LoginPageIdpInfo {
        private List<String> customerIdpWebDomains;
        private boolean hasCustomerSamlIdps;
        private boolean hasCustomerOAuthIdps;

        public List<String> getCustomerIdpWebDomains() {
            return customerIdpWebDomains;
        }

        public void setCustomerIdpWebDomains(List<String> customerIdpWebDomains) {
            this.customerIdpWebDomains = customerIdpWebDomains;
        }

        public boolean isHasCustomerSamlIdps() {
            return hasCustomerSamlIdps;
        }

        public void setHasCustomerSamlIdps(boolean hasCustomerSamlIdps) {
            this.hasCustomerSamlIdps = hasCustomerSamlIdps;
        }

        public boolean isHasCustomerOAuthIdps() {
            return hasCustomerOAuthIdps;
        }

        public void setHasCustomerOAuthIdps(boolean hasCustomerOAuthIdps) {
            this.hasCustomerOAuthIdps = hasCustomerOAuthIdps;
        }
    }
}
