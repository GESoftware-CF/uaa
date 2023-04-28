package org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.uilocators;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class GeSsoLogin {
    WebDriver driver;

    //Constructor that will be automatically called as soon as the object of the class is created
    public GeSsoLogin(WebDriver driver) {
        this.driver = driver;
    }

    //Locator for username field
    By uName =By.id("identifierInput");

    //Locator for nextButton field
    By nextButton = By.xpath("//button[@id='post-button']");

    By passwordTextBox= By.xpath("//input[@id='password']");

    By LoginButton=By.xpath("//button[@id='remember-me-login-button']");

    //Method to enter username
    public void enterUsername(String user) {
        driver.findElement(uName).sendKeys(user);
    }

    public void enterPassword(String password) {
        driver.findElement(passwordTextBox).sendKeys(password);
    }

    //Method to click on next button
    public void nextButton() {
        driver.findElement(nextButton).click();
    }

    public void loginButton(){
        driver.findElement(LoginButton).click();
    }

}
