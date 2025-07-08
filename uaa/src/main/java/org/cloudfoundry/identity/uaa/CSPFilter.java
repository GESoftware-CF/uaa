package org.cloudfoundry.identity.uaa;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebFilter(urlPatterns = "/*") // Apply this filter to all incoming requests
@Component
@Order(1) // Ensures this filter runs early in the filter chain
public class CSPFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(CSPFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Filter initialization if needed
        logger.info("CSPFilter initialized.");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
        throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

//httpResponse.setHeader("Content-Security-Policy-Report-Only",
     //   "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");
        // 1. The 'Report-To' HTTP header:
        //    Defines a named endpoint group ('csp-endpoint') for the Reporting API.
        //    'max_age' indicates how long the browser should cache this configuration.
        //    'url' specifies the endpoint where reports for this group should be sent.
        httpResponse.setHeader(
                "Report-To",
                "{ \"group\":\"csp-endpoint\", \"max_age\":300, \"endpoints\":[{ \"url\":\"/api/csp-reports\" }] }"
        );

        // 2. The 'Content-Security-Policy-Report-Only' HTTP header:
        //    Defines your CSP directives.
        //    - 'report-to csp-endpoint;' is for modern browsers (references the group above).
        //    - 'report-uri /api/csp-report-uri;' is for older browsers (points directly to URL).
        httpResponse.setHeader(
                "Content-Security-Policy-Report-Only",
                "default-src 'self';" +          // Allow resources from same origin by default
                        "script-src 'self';" +           // Allow scripts only from the same origin
                        "style-src 'self';" +            // Allow styles only from the same origin
                        "img-src 'self' data:;" +        // Allow images from same origin and data URIs
                        "object-src 'none';" +           // Disallow <object>, <embed>, <applet>
                        "form-action 'self';" +          // Restrict form submissions to same origin
                        "base-uri 'self';" +             // Restrict base tag
                        "frame-ancestors 'none';" +
                        "font-src 'self' https://cdn.predix-ui.com; img-src 'self';" +
                        "frame-src 'self';"+
                        "report-to csp-endpoint;" +      // Directive for modern browsers (uses Report-To header)
                        "report-uri /api/csp-report-uri;" // Directive for older browsers (direct URL)
        );
//Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self'";
        logger.debug("Added CSP-Report-Only and Report-To headers for URL: {}", httpRequest.getRequestURI());

        // Continue with the next filter in the chain
        chain.doFilter(servletRequest, servletResponse);
        logger.debug("CspReportingFilter finished for URI: {}", ((HttpServletRequest) servletRequest).getRequestURI());
    }

    @Override
    public void destroy() {
        // Clean up resources if needed
        logger.info("CSPFilter destroyed.");
    }
}