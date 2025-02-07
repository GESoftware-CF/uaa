package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.UaaConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Represents a Java-managed {@link SecurityFilterChain}. This allows mixing
 * XML-based configuration and Java-based configuration.
 * <p>
 * See {@link UaaConfiguration#aggregateSpringSecurityFilterChain(WebSecurityConfiguration, List)} for more information.
 *
 * @deprecated Remove this once there are no more XML-based filter chains.
 */
@Deprecated
public class UaaFilterChain implements SecurityFilterChain {

    private final SecurityFilterChain chain;

    public UaaFilterChain(SecurityFilterChain chain) {
        this.chain = chain;
    }

    @Override
    public List<Filter> getFilters() {
        return this.chain.getFilters();
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return this.chain.matches(request);
    }
}
