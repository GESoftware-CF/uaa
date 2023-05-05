package org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.uilocators;

import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class GeSsoSPlogin {
    WebDriver driver;

    public GeSsoSPlogin(WebDriver driver) {
        this.driver = driver;
    }

    By Gesso = By.xpath("//a[@class='saml-login-link']");


    public void clickOnSignInByGesso() {
        driver.findElement(Gesso).click();
    }


}
