package org.cloudfoundry.identity.uaa.web;

/**
 * The order for all the filter chains in the UAA. The name references
 * Spring Security's {@code FilterOrderRegistration}.
 */
public class FilterChainOrder {

    // Order of filters handling user login features, formerly defined by
    // ordering filter chains in login-ui.xml
    public static final int AUTOLOGIN_AUTHORIZE = 1200;
    public static final int AUTOLOGIN_CODE = 1201;
    public static final int AUTOLOGIN = 1202;
    public static final int INVITATIONS = 1203;
    public static final int INVITE = 1204;
    public static final int RESET_PASSWORD = 1205;
    public static final int LOGIN_PUBLIC_OPERATIONS = 1206;
    public static final int UI_SECURITY = 1207;

}