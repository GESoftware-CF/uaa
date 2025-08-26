package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.event.UserLoginSuccessEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class UserLoginSuccessEventListener {
    @EventListener
    public void handleUserLoginSuccess(UserLoginSuccessEvent event) {
        UaaUser user = event.getUser();
        boolean isNameChanged = event.isNameChanged();
        boolean isEmailChanged = event.isEmailChanged();

        System.out.println("User logged in: " + user.getUsername());
        if (isNameChanged) {
            System.out.println("User's name has changed.");
        }
        if (isEmailChanged) {
            System.out.println("User's email has changed.");
        }
    }
}