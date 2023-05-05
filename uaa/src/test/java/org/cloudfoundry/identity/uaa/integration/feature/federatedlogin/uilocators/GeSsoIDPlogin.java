package org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.uilocators;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class GeSsoIDPlogin {
    WebDriver driver;

    public GeSsoIDPlogin(WebDriver driver) {
        this.driver = driver;
    }

    By IDPuserName = By.xpath("//input[@name='username']");
    By IDPPassword = By.xpath("//input[@name='password']");
    By clickOnSignIn = By.xpath("//input[@value='Sign in']");
    By welcomecheck = By.xpath("//h1[contains(text(), 'Welcome to testzone1!')]");

    public void enterIDPuserName(String EnterIDPuserName) {
        driver.findElement(IDPuserName).sendKeys(EnterIDPuserName);
    }

    public void enterIDPPassword(String enterIDPPassword) {
        driver.findElement(IDPPassword).sendKeys(enterIDPPassword);
    }

    public void clickOnSignIn() {
        driver.findElement(clickOnSignIn).click();
    }


    public void headLineCheck() {
        driver.findElement(welcomecheck).click();
    }
}


