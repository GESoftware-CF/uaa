package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationEvent;

public class UserLoginSuccessEvent extends ApplicationEvent {
    private final UaaUser user;
    private final boolean isNameChanged;
    private final boolean isEmailChanged;

    public UserLoginSuccessEvent(Object source, UaaUser user, boolean isNameChanged, boolean isEmailChanged) {
        super(source);
        this.user = user;
        this.isNameChanged = isNameChanged;
        this.isEmailChanged = isEmailChanged;
    }

    public UaaUser getUser() {
        return user;
    }

    public boolean isNameChanged() {
        return isNameChanged;
    }

    public boolean isEmailChanged() {
        return isEmailChanged;
    }
}