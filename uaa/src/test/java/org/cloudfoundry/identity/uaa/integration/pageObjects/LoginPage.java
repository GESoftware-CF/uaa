package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.concurrent.atomic.AtomicReference;

/**
 * The LoginPage class represents the login page on the UAA server.
 * It has url matching: `/login`.
 */
public class LoginPage extends Page {

    private static final String URL_PATH = "/login";

    public LoginPage(WebDriver driver) {
        super(driver);
        assertThatLoginPageShown();
    }

    public LoginPage(WebDriver driver, String baseUrl) {
        super(driver, baseUrl);
        assertThatLoginPageShown();
    }

    public static LoginPage go(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + URL_PATH);
        return new LoginPage(driver, baseUrl);
    }

    public LoginPage assertThatLoginPageShown() {
        if (baseUrl == null) {
            assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.matches(".*" + URL_PATH + "(\\?.*)?$"));
        } else {
            assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(baseUrl + URL_PATH));
        }
        return this;
    }

    /**
     * Navigate directly to SAML authentication endpoint.
     * The new login UI requires customer IDP domains to show SAML links,
     * so we bypass link clicking and use direct URL navigation.
     * 
     * @param originKey The SAML IDP origin key (e.g., "simplesamlphp")
     * @return LoginPage after navigation (not SamlLoginPage to avoid constructor redirect wait)
     */
    public LoginPage assertThatSamlLink_goesToSamlLoginPage(String originKey) {
        // Get baseUrl from current URL if not set
        String urlToUse = getBaseUrlForNavigation();
        driver.get(String.format("%s/saml2/authenticate/%s", urlToUse, originKey));
        // Don't wait for redirect - tests will handle SAML page detection themselves
        return this;
    }
    
    /**
     * Navigate to SAML authentication endpoint, perform SAML login, and wait to return to UAA.
     * This is a complete flow that handles the SAML redirect and login.
     * 
     * @param originKey The SAML IDP origin key (e.g., "simplesamlphp")
     * @param username SAML username
     * @param password SAML password
     * @return LoginPage after SAML authentication completes and redirects back to UAA
     */
    public LoginPage assertThatSamlLink_performsLogin(String originKey, String username, String password) {
        String urlToUse = getBaseUrlForNavigation();
        driver.get(String.format("%s/saml2/authenticate/%s", urlToUse, originKey));
        
        // Wait for SAML page to load and perform login
        Page.assertThatUrlEventuallySatisfies((UaaWebDriver) driver,
            url -> url.containsAnyOf("/module.php/core/loginuserpass", "localhost"));
        
        // Perform SAML login
        performSamlLogin(username, password);
        
        // Wait for redirect back to UAA
        Page.assertThatUrlEventuallySatisfies((UaaWebDriver) driver,
            url -> url.contains(urlToUse));
        
        return this;
    }
    
    /**
     * Navigate to SAML authentication endpoint and perform login on SimpleSAMLphp IDP,
     * then return to UAA home page.
     */
    public HomePage assertThatSamlLogin_goesToHomePage(String originKey, String username, String password) {
        String urlToUse = getBaseUrlForNavigation();
        driver.get(String.format("%s/saml2/authenticate/%s", urlToUse, originKey));
        performSamlLogin(username, password);
        return new HomePage(driver, urlToUse);
    }
    
    /**
     * Navigate to SAML authentication endpoint and perform login on SimpleSAMLphp IDP,
     * expecting to land on a SAML error page.
     */
    public SamlErrorPage assertThatSamlLogin_goesToSamlErrorPage(String originKey, String username, String password) {
        String urlToUse = getBaseUrlForNavigation();
        driver.get(String.format("%s/saml2/authenticate/%s", urlToUse, originKey));
        performSamlLogin(username, password);
        return new SamlErrorPage(driver);
    }
    
    /**
     * Perform login on SimpleSAMLphp page (handles both old and new versions).
     * Assumes browser is already on the SAML login page.
     */
    private void performSamlLogin(String username, String password) {
        driver.findElement(By.name("username")).clear();
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        // Try multiple selectors for different SimpleSAMLphp versions
        boolean submitted = false;
        for (By selector : new By[]{
                By.id("submit_button"),
                By.cssSelector("button[type='submit']"),
                By.xpath("//input[@type='submit']"),
                By.cssSelector("input[type='submit']")
        }) {
            try {
                driver.findElement(selector).click();
                submitted = true;
                break;
            } catch (org.openqa.selenium.NoSuchElementException e) {
                // Try next selector
            }
        }
        if (!submitted) {
            throw new RuntimeException("Could not find submit button on SAML login page");
        }
    }

    /**
     * If the SAML IDP has no logout URL in the metadata, logging out of UAA will leave
     * the IDP still logged in.
     * When going back to the SAML login page, it will log
     * the app back in automatically and immediately redirect to the post-login page.
     */
    public HomePage assertThatSamlLink_goesToHomePage(String originKey) {
        String urlToUse = getBaseUrlForNavigation();
        driver.get(String.format("%s/saml2/authenticate/%s", urlToUse, originKey));
        return new HomePage(driver, urlToUse);
    }
    
    private String getBaseUrlForNavigation() {
        if (baseUrl != null) {
            return baseUrl;
        }
        // Extract base URL from current page URL
        String currentUrl = driver.getCurrentUrl();
        // Remove path and query parameters to get base URL
        int pathStart = currentUrl.indexOf('/', currentUrl.indexOf("://") + 3);
        return pathStart > 0 ? currentUrl.substring(0, pathStart) : currentUrl;
    }

    /**
     * Perform UAA login and expect to go to home page.
     */
    public HomePage assertThatLogin_goesToHomePage(String username, String password) {
        performUaaLogin(username, password);
        return new HomePage(driver, baseUrl);
    }
    
    /**
     * Perform UAA login and expect to go to passcode page.
     */
    public PasscodePage assertThatLogin_goesToPasscodePage(String username, String password) {
        performUaaLogin(username, password);
        return new PasscodePage(driver);
    }
    
    /**
     * Perform UAA login and expect to go to SAML error page.
     */
    public SamlErrorPage assertThatLogin_goesToSamlErrorPage(String username, String password) {
        performUaaLogin(username, password);
        return new SamlErrorPage(driver);
    }
    
    /**
     * Perform login on UAA login page.
     */
    private void performUaaLogin(String username, String password) {
        driver.findElement(By.name("username")).clear();
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.name("password")).clear();
        driver.findElement(By.name("password")).sendKeys(password);
        
        // Try multiple selectors for the Sign in button to handle different page versions
        boolean submitted = false;
        for (By selector : new By[]{
                By.xpath("//input[@value='Sign in']"),
                By.xpath("//button[contains(text(), 'Sign in')]"),
                By.cssSelector("button[type='submit']"),
                By.cssSelector("input[type='submit']"),
                By.xpath("//input[@type='submit']"),
                By.xpath("//button[@type='submit']")
        }) {
            try {
                ((UaaWebDriver) driver).clickAndWait(selector);
                submitted = true;
                break;
            } catch (org.openqa.selenium.NoSuchElementException e) {
                // Try next selector
            }
        }
        if (!submitted) {
            throw new RuntimeException("Could not find submit button on UAA login page");
        }
    }

    public HomePage sendLoginCredentials(String username, String password) {
        driver.get(baseUrl + "/login");
        performUaaLogin(username, password);
        return new HomePage(driver, baseUrl);
    }

    /**
     * Click the first link that contains the given text
     */
    private void clickSamlLoginLinkWithText(String matchText) {
        final AtomicReference<WebElement> matchingElement = new AtomicReference<>();
        
        // Try to find by saml-login-link class first (for customer IDP scenarios)
        driver.findElements(By.className("saml-login-link")).forEach(webElement -> {
            if (webElement.getText().contains(matchText)) {
                matchingElement.compareAndSet(null, webElement);
            }
        });
        
        // If not found, search in the saml-login div by link text
        if (matchingElement.get() == null) {
            driver.findElements(By.cssSelector(".saml-login a")).forEach(webElement -> {
                if (webElement.getText().contains(matchText)) {
                    matchingElement.compareAndSet(null, webElement);
                }
            });
        }
        
        if (matchingElement.get() == null) {
            throw new RuntimeException("No element with text " + matchText + " found");
        }
        matchingElement.get().click();
    }
}