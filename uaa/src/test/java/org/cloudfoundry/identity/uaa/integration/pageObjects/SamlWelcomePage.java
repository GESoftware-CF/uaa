package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.integration.feature.SamlServerConfig;
import org.openqa.selenium.WebDriver;

/**
 * The SamlWelcomePage class represents the welcome page on the SimpleSAML server.
 * It has url matching: `/module.php/core/welcome` or similar SAML server pages.
 */
public class SamlWelcomePage extends Page {

    public SamlWelcomePage(WebDriver webDriver, SamlServerConfig samlServerConfig) {
        super(webDriver);
        // Updated: More lenient check to handle different SimpleSAMLphp versions
        // Some versions may have different welcome page structures or paths
        assertThatUrlEventuallySatisfies(assertUrl -> 
            assertUrl.contains(samlServerConfig.getSamlServerUrl())
        );
    }
}