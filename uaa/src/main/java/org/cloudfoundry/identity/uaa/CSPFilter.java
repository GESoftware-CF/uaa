package org.cloudfoundry.identity.uaa;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class CSPFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Filter initialization if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;

//httpResponse.setHeader("Content-Security-Policy-Report-Only",
     //   "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");
        httpResponse.setHeader(
                "Content-Security-Policy-Report-Only",
                "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; form-action 'self'; report-to csp-endpoint"
        );

        // Add Report-To header
        httpResponse.setHeader(
                "Report-To",
                "{ \"group\":\"csp-endpoint\", \"max_age\":10886400, \"endpoints\":[{ \"url\":\"/api/csp-reports\" }] }"
        );
//Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self'";
        // Continue with the next filter in the chain
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Clean up resources if needed
    }
}