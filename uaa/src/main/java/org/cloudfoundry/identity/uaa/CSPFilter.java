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

        // Set the CSP header
       httpResponse.setHeader("Content-Security-Policy",
                              "object-src 'none'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; block-all-mixed-content; upgrade-insecure-requests; require-sri-for script style; require-trusted-types-for 'script';");

        // Continue with the next filter in the chain
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Clean up resources if needed
    }
}