/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ReAuthenticationRequiredFilterTests {

    private ReAuthenticationRequiredFilter filter;
    private UaaAuthentication authentication;
    private MockHttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    void setup() {
        filter = new ReAuthenticationRequiredFilter("cloudfoundry-login");
        authentication = mock(UaaAuthentication.class);
        request = new MockHttpServletRequest();
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        request.setContextPath("");
        request.setServletPath("/oauth/authorize");
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void request_with_prompt_login() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setParameter("client_id", "testclient");
        request.setParameter("prompt", "login");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(same(request), same(response));
        org.mockito.ArgumentCaptor<String> redirectCaptor = forClass(String.class);
        verify(response).sendRedirect(redirectCaptor.capture());
        var redirectParameters = UriComponentsBuilder.fromUriString(redirectCaptor.getValue()).build().getQueryParams();
        assertThat(redirectParameters.getFirst("prompt")).isEqualTo("login");
        assertThat(redirectParameters.getFirst(ReAuthenticationRequiredFilter.REAUTHENTICATION_MARKER_PARAMETER))
            .isNotBlank();
        }

        @Test
        void promptLoginMarkerIsStrippedAndDoesNotCauseReauthenticationLoop() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setParameter("client_id", "testclient");
        request.setParameter("redirect_uri", "https://client.example/callback");
        request.setParameter("response_type", "code");
        request.setParameter("state", "state-123");
        request.setParameter("prompt", "login");

        org.mockito.ArgumentCaptor<String> redirectCaptor = forClass(String.class);
        filter.doFilterInternal(request, response, chain);
        verify(response).sendRedirect(redirectCaptor.capture());
        String marker = UriComponentsBuilder.fromUriString(redirectCaptor.getValue()).build()
            .getQueryParams().getFirst(ReAuthenticationRequiredFilter.REAUTHENTICATION_MARKER_PARAMETER);

        request.setParameter(ReAuthenticationRequiredFilter.REAUTHENTICATION_MARKER_PARAMETER, marker);
        filter.doFilterInternal(request, response, chain);

        org.mockito.ArgumentCaptor<ServletRequest> requestCaptor = forClass(ServletRequest.class);
        verify(chain).doFilter(requestCaptor.capture(), org.mockito.ArgumentMatchers.same(response));
        jakarta.servlet.http.HttpServletRequest retryRequest =
            (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
        assertThat(retryRequest.getParameter("prompt")).isEqualTo("login");
        assertThat(retryRequest.getParameter(ReAuthenticationRequiredFilter.REAUTHENTICATION_MARKER_PARAMETER))
            .isNull();
        assertThat(request.getSession(false)
            .getAttribute(ReAuthenticationRequiredFilter.REAUTHENTICATION_MARKER_SESSION_ATTRIBUTE)).isNull();

        MockHttpServletRequest authenticatedReturn = new MockHttpServletRequest();
        authenticatedReturn.setServletPath("/oauth/authorize");
        authenticatedReturn.setSession(request.getSession(false));
        authenticatedReturn.setParameter("client_id", "testclient");
        authenticatedReturn.setParameter("redirect_uri", "https://client.example/callback");
        authenticatedReturn.setParameter("response_type", "code");
        authenticatedReturn.setParameter("state", "state-123");
        authenticatedReturn.setParameter("prompt", "login");
        filter.doFilterInternal(authenticatedReturn, response, chain);
        verify(chain, times(2)).doFilter(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.same(response));
        assertThat(authenticatedReturn.getSession(false)
            .getAttribute(ReAuthenticationRequiredFilter.PENDING_AUTHORIZATION_SESSION_ATTRIBUTE)).isNull();
    }

    @Test
    void request_with_prompt_none() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setParameter("prompt", "none");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    void request_with_max_age_redirect_expected() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.getAuthenticatedTime()).thenReturn(System.currentTimeMillis() - 2000);
        request.setParameter("client_id", "testclient");
        request.setParameter("max_age", "1");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(same(request), same(response));
        // verify that the redirect was happening and the url does not contain the max_age parameter
        verify(response, times(1)).sendRedirect(matches("^((?!max_age).)*$"));
    }

    @Test
    void request_with_max_age_redirect_not_expected() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.getAuthenticatedTime()).thenReturn(System.currentTimeMillis());
        request.setParameter("client_id", "testclient");
        request.setParameter("max_age", "1");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    void request_without_prompt_and_max_age() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setServletPath("/saml/SingleLogout/alias/cloudfoundry-login");
        request.setParameter("client_id", "testclient");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }
}