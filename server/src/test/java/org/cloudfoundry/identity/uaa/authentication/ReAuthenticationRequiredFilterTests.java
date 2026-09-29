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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockHttpServletResponse;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import java.net.URI;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.anyString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.matches;
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
        // verify that the redirect is happening and the redirect url does not contain
        // the prompt parameter
        verify(response, times(1)).sendRedirect(matches("^((?!prompt).)*$"));
        assertThat(request.getSession(false)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = { "oidc_prompt", "saml_prompt" })
    void shouldNotKeepAuthenticatedUserAfterIdpReauthenticationRedirect(String promptParameter) throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setRequestURI("/oauth/authorize");
        request.setServletPath("/oauth/authorize");
        request.setParameter(promptParameter, "login");

        filter.doFilterInternal(request, new MockHttpServletResponse(), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void request_with_prompt_none() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setParameter("prompt", "none");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = { "oidc_prompt", "saml_prompt" })
    void shouldPreserveReauthenticationOnlyForItsContinuation(String promptParameter) throws Exception {
        request.setRequestURI("/oauth/authorize");
        request.setServletPath("/oauth/authorize");
        request.setParameter("client_id", "testclient");
        request.setParameter(promptParameter, "login");
        MockHttpServletResponse redirectResponse = new MockHttpServletResponse();
        filter.doFilterInternal(request, redirectResponse, chain);

        String continuationUrl = redirectResponse.getRedirectedUrl();
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        MockHttpServletRequest continuation = new MockHttpServletRequest("GET", "/oauth/authorize");
        continuation.setServletPath("/oauth/authorize");
        continuation.setQueryString(URI.create(continuationUrl).getRawQuery());
        continuation.setSession(session);
        filter.doFilterInternal(continuation, response, chain);
        SessionUtils.setSavedRequestSession(session,
                new UaaSavedRequestCache.ClientRedirectSavedRequest(continuation, continuationUrl));
        assertThat(SessionUtils.isForceIdpReauthentication(session)).isTrue();
        assertThat(SessionUtils.isOidcReauthentication(session))
                .isEqualTo(SessionUtils.OIDC_PROMPT_PARAMETER.equals(promptParameter));
        assertThat(SessionUtils.isSamlReauthentication(session))
                .isEqualTo(SessionUtils.SAML_PROMPT_PARAMETER.equals(promptParameter));
        assertThat(UriComponentsBuilder.fromUriString(continuationUrl).build().getQueryParams())
                .doesNotContainKeys("prompt", "oidc_prompt", "saml_prompt");

        MockHttpServletRequest nextAuthorization = new MockHttpServletRequest("GET", "/oauth/authorize");
        nextAuthorization.setServletPath("/oauth/authorize");
        nextAuthorization.setQueryString("client_id=testclient");
        nextAuthorization.setSession(session);
        filter.doFilterInternal(nextAuthorization, response, chain);
        assertThat(session.getAttribute(SessionUtils.FORCE_IDP_REAUTHENTICATION)).isNull();
        assertThat(SessionUtils.isForceIdpReauthentication(session)).isFalse();
    }

    @Test
    void shouldRejectSavedRequestFromAnotherAuthorization() {
        MockHttpSession session = new MockHttpSession();
        SessionUtils.startIdpReauthentication(session,
                "http://localhost/oauth/authorize?client_id=first", true, false);
        SessionUtils.setSavedRequestSession(session,
                new UaaSavedRequestCache.ClientRedirectSavedRequest(request,
                        "http://localhost/oauth/authorize?client_id=second"));
        assertThat(SessionUtils.isForceIdpReauthentication(session)).isFalse();
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
        // verify that the redirect was happening and the url does not contain the
        // max_age parameter
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