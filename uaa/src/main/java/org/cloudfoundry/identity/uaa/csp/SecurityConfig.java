package org.cloudfoundry.identity.uaa.csp;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter { // Extend WebSecurityConfigurerAdapter for SB 2.6.x

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() // Use authorizeRequests() for Spring Security 5.x
                // Allow unauthenticated POST requests to both CSP reporting endpoints
                .antMatchers("/api/csp-reports").permitAll()
                .antMatchers("/api/csp-report-uri").permitAll()
                // Allow access to your static HTML page and other static resources
                .antMatchers("/").permitAll() // For your index.html
                .antMatchers("/**").permitAll() // General rule for other static assets (CSS, JS)
                // All other requests require authentication (uncomment and adjust if needed)
                // .anyRequest().authenticated()
                .and()
                .csrf().disable(); // Disable CSRF for API endpoints, adjust as per your application's needs
    }
}