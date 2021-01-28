package org.cloudfoundry.identity.uaa.web.beans;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.web.context.annotation.RequestScope;

import javax.servlet.http.HttpServletRequest;

public class UaaSessionConfig {
    @Bean
    @RequestScope
    public CookieSerializer uaaCookieSerializer(
            final @Value("${servlet.session-cookie.max-age:-1}") int cookieMaxAge,
            final HttpServletRequest request
    ) {
        UaaDefaultCookieSerializer cookieSerializer = new UaaDefaultCookieSerializer();

        if (request.isSecure()) {
            cookieSerializer.setSameSite("None");
        } else {
            cookieSerializer.setSameSite(null);
        }

        cookieSerializer.setCookieMaxAge(cookieMaxAge);
        cookieSerializer.setCookieName("JSESSIONID");

        return cookieSerializer;
    }
}
