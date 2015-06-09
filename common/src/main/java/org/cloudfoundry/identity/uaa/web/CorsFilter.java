/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009, 2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

public class CorsFilter extends OncePerRequestFilter {

    private static final Log LOG = LogFactory.getLog(CorsFilter.class);

    /**
     * A comma delimited list of regular expression patterns that defines which
     * UAA URLs allow the "X-Requested-With" header in CORS requests.
     */
    @Value("#{'${cors.xhr.allowed.urls:^$}'.split(',')}")
    private List<String> corsXhrAllowedUrls;

    private final List<Pattern> corsXhrAllowedUrlPatterns = new ArrayList<Pattern>();

    /**
     * A comma delimited list of regular expression patterns that define which
     * origins are allowed to use the "X-Requested-With" header in CORS
     * requests.
     */
    @Value("#{'${cors.xhr.allowed.origins:^$}'.split(',')}")
    private List<String> corsXhrAllowedOrigins;

    private final List<Pattern> corsXhrAllowedOriginPatterns = new ArrayList<Pattern>();

    @PostConstruct
    public void initialize() {

        for (String allowedUrl : this.corsXhrAllowedUrls) {
            try {
                this.corsXhrAllowedUrlPatterns.add(Pattern.compile(allowedUrl));

                if (LOG.isDebugEnabled()) {
                    LOG.debug(String
                            .format("URL '%s' allows 'X-Requested-With' header in CORS requests.", allowedUrl));
                }
            } catch (PatternSyntaxException patternSyntaxException) {
                LOG.error("Invalid regular expression pattern in cors.xhr.allowed.urls " + allowedUrl);
            }
        }

        for (String allowedOrigin : this.corsXhrAllowedOrigins) {
            try {
                this.corsXhrAllowedOriginPatterns.add(Pattern.compile(allowedOrigin));

                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Origin '%s' allowed 'X-Requested-With' header in CORS requests."
                            + allowedOrigin));
                }
            } catch (PatternSyntaxException patternSyntaxException) {
                LOG.error("Invalid regular expression pattern in cors.xhr.allowed.origins " + allowedOrigin);
            }
        }
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain filterChain) throws ServletException, IOException {
        response.addHeader("Access-Control-Allow-Origin", "*");
        if (request.getHeader("Access-Control-Request-Method") != null && "OPTIONS".equals(request.getMethod())) {
            // CORS "pre-flight" request
            response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            String allowedHeaders = getAllowedHeaders(request);
            response.addHeader("Access-Control-Allow-Headers", allowedHeaders);
            response.addHeader("Access-Control-Max-Age", "1728000");
        } else {
            filterChain.doFilter(request, response);
        }
    }

    String getAllowedHeaders(final HttpServletRequest request) {

        String url = request.getRequestURI();
        String method = request.getMethod();
        String origin = request.getHeader(HttpHeaders.ORIGIN);

        if (method.equalsIgnoreCase("GET") && isCorsXhrAllowedForRequestUrl(url) && StringUtils.isNotEmpty(origin)
                && isCorsXhrAllowedForRequestOrigin(origin)) {
            return HttpHeaders.AUTHORIZATION + ", X-Requested-With";
        }

        return HttpHeaders.AUTHORIZATION;
    }

    boolean isCorsXhrAllowedForRequestUrl(final String url) {
        for (Pattern pattern : this.corsXhrAllowedUrlPatterns) {
            // Making sure that the pattern matches
            if (pattern.matcher(url).find()) {
                return true;
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("The '%s' URL does not allow CORS requests with the 'X-Requested-With' header.",
                    url));
        }
        return false;
    }

    private boolean isCorsXhrAllowedForRequestOrigin(final String origin) {
        for (Pattern pattern : this.corsXhrAllowedOriginPatterns) {
            // Making sure that the pattern matches
            if (pattern.matcher(origin).find()) {
                return true;
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format(
                    "The '%s' origin is not allowed to make CORS requests with the 'X-Requested-With' header.",
                    origin));
        }
        return false;
    }
}