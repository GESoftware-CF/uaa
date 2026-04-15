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
 * Can be accessed directly in templates via: @externalIdpService
 */
@Service("externalIdpService")
public class ExternalIdpWebDomainsService {

    private static final Logger logger = LoggerFactory.getLogger(ExternalIdpWebDomainsService.class);

    private final List<String> externalIdpWebDomains;

    public ExternalIdpWebDomainsService(
            @Value("${external_idp.web_domains:}") List<String> externalIdpWebDomains) {
        this.externalIdpWebDomains = externalIdpWebDomains != null ? externalIdpWebDomains : Collections.emptyList();
        logger.info("ExternalIdpWebDomainsService initialized with {} domains", this.externalIdpWebDomains.size());
        logger.debug("External IDP web domains configured: {}", this.externalIdpWebDomains);
    }

    /**
     * Gets the configured external IDP web domains.
     *
     * @return List of external IDP web domains
     */
    public List<String> getExternalIdpWebDomains() {
        logger.debug("getExternalIdpWebDomains() called, returning {} domains", externalIdpWebDomains.size());
        return externalIdpWebDomains;
    }

    /**
     * Checks if there are any external IDPs configured.
     *
     * @return true if external IDP web domains are configured
     */
    public boolean hasExternalIdpWebDomains() {
        boolean hasExternalIdps = externalIdpWebDomains != null && !externalIdpWebDomains.isEmpty();
        logger.debug("hasExternalIdpWebDomains() called, returning: {}", hasExternalIdps);
        return hasExternalIdps;
    }

    /**
     * Determines if there are external SAML identity providers that should be displayed
     * with the "Or sign in with:" separator.
     *
     * @param samlIdentityProviders Map of SAML identity providers
     * @return true if there are external SAML IDPs to display
     */
    public boolean hasExternalSamlIdps(Map<String, SamlIdentityProviderDefinition> samlIdentityProviders) {
        logger.debug("hasExternalSamlIdps() called with {} SAML providers", 
                     samlIdentityProviders != null ? samlIdentityProviders.size() : 0);
        
        if (!hasExternalIdpWebDomains() || samlIdentityProviders == null || samlIdentityProviders.isEmpty()) {
            logger.debug("No external SAML IDPs: hasExternalIdpWebDomains={}, samlProviders={}", 
                         hasExternalIdpWebDomains(), samlIdentityProviders != null ? "not null" : "null");
            return false;
        }

        boolean result = samlIdentityProviders.values().stream().anyMatch(idp ->
                idp.isShowSamlLink() &&
                externalIdpWebDomains.stream().anyMatch(domain -> !idp.getMetaDataLocation().contains(domain))
        );
        logger.debug("hasExternalSamlIdps() returning: {}", result);
        return result;
    }

    /**
     * Determines if there are customer OAuth links that should be displayed
     * with the "Or sign in with:" separator.
     *
     * @param oauthLinks Map of OAuth authentication URLs to link text
     * @return true if there are customer OAuth links to display
     */
    public boolean hasExternalOAuthLinks(Map<String, String> oauthLinks) {
        logger.debug("hasExternalOAuthLinks() called with {} OAuth links", 
                     oauthLinks != null ? oauthLinks.size() : 0);
        
        if (!hasExternalIdpWebDomains() || oauthLinks == null || oauthLinks.isEmpty()) {
            logger.debug("No external OAuth links: hasExternalIdpWebDomains={}, oauthLinks={}", 
                         hasExternalIdpWebDomains(), oauthLinks != null ? "not null" : "null");
            return false;
        }

        boolean result = oauthLinks.values().stream().anyMatch(linkText ->
                externalIdpWebDomains.stream().anyMatch(domain -> !linkText.contains(domain))
        );
        logger.debug("hasExternalOAuthLinks() returning: {}", result);
        return result;
    }

    /**
     * Checks if a given metadata location or link text is NOT a customer IDP.
     * This is useful for determining whether to show the "Or sign in with:" separator.
     *
     * @param metadataOrLinkText The metadata location or link text to check
     * @return true if this is not a customer IDP (i.e., should be displayed with separator)
     */
    public boolean isNotExternalIdp(String metadataOrLinkText) {
        if (!hasExternalIdpWebDomains() || metadataOrLinkText == null) {
            return true;
        }

        return externalIdpWebDomains.stream().noneMatch(metadataOrLinkText::contains);
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
        info.setExternalIdpWebDomains(externalIdpWebDomains);
        info.setHasExternalSamlIdps(hasExternalSamlIdps(samlIdentityProviders));
        
        // For OAuth links, we need to check if there are any non-external OAuth providers
        // This will be calculated when OAuth links are created
        info.setHasExternalOAuthIdps(false); // Will be updated by the endpoint
        
        return info;
    }

    /**
     * Checks if there are any customer (non-external) IDPs that should be displayed
     * with the "Or sign in with:" separator.
     * This method can be called directly from templates.
     *
     * @param samlIdpDefinitions List of SAML IDP definitions from the model
     * @param oauthLinks List of OAuth link entries from the model
     * @return true if there are customer IDPs to display
     */
    public boolean hasCustomerIdps(List<?> samlIdpDefinitions, List<?> oauthLinks) {
        logger.debug("hasCustomerIdps() called with {} SAML IDPs and {} OAuth links",
                     samlIdpDefinitions != null ? samlIdpDefinitions.size() : 0,
                     oauthLinks != null ? oauthLinks.size() : 0);
        
        if (!hasExternalIdpWebDomains()) {
            logger.debug("No external IDP web domains configured, returning false");
            return false;
        }

        // Check SAML IDPs
        if (samlIdpDefinitions != null && !samlIdpDefinitions.isEmpty()) {
            for (Object obj : samlIdpDefinitions) {
                if (obj instanceof SamlIdentityProviderDefinition idp) {
                    if (idp.isShowSamlLink() && 
                        externalIdpWebDomains.stream().noneMatch(domain -> idp.getMetaDataLocation().contains(domain))) {
                        logger.debug("Found customer SAML IDP: {}", idp.getLinkText());
                        return true;
                    }
                }
            }
        }

        // Check OAuth links
        //with key as link text and value as URL
        if (oauthLinks != null && !oauthLinks.isEmpty()) {
            for (Object obj : oauthLinks) {
                if (obj instanceof java.util.Map.Entry<?, ?> entry) {
                    String linkText = entry.getKey() != null ? entry.getKey().toString() : "";
                    if (externalIdpWebDomains.stream().noneMatch(linkText::contains)) {
                        logger.debug("Found customer OAuth link: {}", linkText);
                        return true;
                    }
                }
            }
        }

        logger.debug("No customer IDPs found");
        return false;
    }

    /**
     * DTO class to hold IDP information for the login page.
     */
    public static class LoginPageIdpInfo {
        private List<String> externalIdpWebDomains;
        private boolean hasExternalSamlIdps;
        private boolean hasExternalOAuthIdps;

        public List<String> getExternalIdpWebDomains() {
            return externalIdpWebDomains;
        }

        public void setExternalIdpWebDomains(List<String> externalIdpWebDomains) {
            this.externalIdpWebDomains = externalIdpWebDomains;
        }

        public boolean isHasExternalSamlIdps() {
            return hasExternalSamlIdps;
        }

        public void setHasExternalSamlIdps(boolean hasExternalSamlIdps) {
            this.hasExternalSamlIdps = hasExternalSamlIdps;
        }

        public boolean isHasExternalOAuthIdps() {
            return hasExternalOAuthIdps;
        }

        public void setHasExternalOAuthIdps(boolean hasExternalOAuthIdps) {
            this.hasExternalOAuthIdps = hasExternalOAuthIdps;
        }
    }
}
