package org.cloudfoundry.identity.uaa.web;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static jakarta.servlet.http.HttpServletResponse.SC_SERVICE_UNAVAILABLE;

@Slf4j
public class LimitedModeUaaFilter extends OncePerRequestFilter {
    // To set Predix UAA limited/degraded mode, use environment variable instead of StatusFile

    public static final String ERROR_CODE = "uaa_unavailable";
    public static final String ERROR_MESSAGE = "UAA intentionally in limited mode, operation not permitted. Please try later.";
    public static final long STATUS_INTERVAL_MS = 5000;
    public static final String DEGRADED = "degraded";

    private Set<String> permittedMethods = emptySet();
    private List<AntPathRequestMatcher> endpoints = emptyList();

    @Override
    protected void doFilterInternal(
            final @NonNull HttpServletRequest request,
            final @NonNull HttpServletResponse response,
            final @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (isEnabled()) {
            logger.debug("Degraded profile is enabled.");
            if (isMethodAllowed(request) || isEndpointAllowed(request)) {
                filterChain.doFilter(request, response);
            } else {
                log.debug("Operation Not permitted in limited mode for URL:{} and method:{}",
                        request.getRequestURI(), request.getMethod());
                Map<String, String> json = getErrorData();
                if (acceptsJson(request)) {
                    response.setStatus(SC_SERVICE_UNAVAILABLE);
                    response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write(JsonUtils.writeValueAsString(json));
                    response.getWriter().flush();
                    response.getWriter().close();
                } else {
                    response.sendError(SC_SERVICE_UNAVAILABLE, json.get("description"));
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    public boolean isEnabled() {
        return Arrays.asList(getEnvironment().getActiveProfiles()).contains(DEGRADED);
    }

    protected Map<String, String> getErrorData() {
        Map<String, String> json = new HashMap<>();
        json.put("error", ERROR_CODE);
        json.put("error_description", ERROR_MESSAGE);
        return json;
    }

    private static boolean acceptsJson(HttpServletRequest request) {
        List<MediaType> mediaTypes = MediaType.parseMediaTypes(request.getHeader(HttpHeaders.ACCEPT));
        return mediaTypes.stream().anyMatch(m -> m.isCompatibleWith(MediaType.APPLICATION_JSON));
    }

    private boolean isMethodAllowed(HttpServletRequest request) {
        return permittedMethods.contains(request.getMethod().toUpperCase());
    }

    private boolean isEndpointAllowed(HttpServletRequest request) {
        return endpoints.stream().anyMatch(m -> m.matches(request));
    }

    public void setPermittedEndpoints(Set<String> permittedEndpoints) {
        this.endpoints = ofNullable(permittedEndpoints)
                .orElse(emptySet())
                .stream()
                .map(AntPathRequestMatcher::new)
                .toList();
    }

    public void setPermittedMethods(Set<String> permittedMethods) {
        this.permittedMethods = ofNullable(permittedMethods).orElse(emptySet());
    }
}
