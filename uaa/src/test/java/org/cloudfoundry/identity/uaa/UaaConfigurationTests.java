/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.YamlConfigurationValidator;
import org.junit.jupiter.api.Test;

import jakarta.validation.ConstraintViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Luke Taylor
 */
class UaaConfigurationTests {

    private final YamlConfigurationValidator<UaaConfiguration> validator = new YamlConfigurationValidator<>(
            new UaaConfiguration.UaaConfigConstructor());

    private void createValidator(final String yaml) {
        validator.setExceptionIfInvalid(true);
        validator.setYaml(yaml);
        validator.afterPropertiesSet();
    }

    @Test
    void validYamlIsOk() {
        createValidator(
                """
                        name: uaa
                        issuer.uri: http://foo.com
                        oauth:
                          clients:
                            cf:
                              id: cf
                              authorized-grant-types: implicit
                          user:
                            authorities:
                              - openid
                              - scim.me
                          openid:
                            fallbackToAuthcode: false""");
    }

    @Test
    void validClientIsOk() {
        createValidator(
                """
                        oauth:
                          clients:
                            cf:
                              id: cf
                              autoapprove: true
                              authorized-grant-types: implicit
                        """);
        assertThat(validator.getObject().oauth.clients).containsKey("cf");
    }

    @Test
    public void validProxyPublicKeyIsOk() throws Exception {
        createValidator(
        "device:\n" +
        "  assertion:\n" +
        "    proxy-public-key: |\n" +
        "      Not-Used\n");
        assertTrue(validator.getObject().device.assertion.proxyPublicKey.contains("Not-Used"));
    }

    @Test
    public void validJwtTokenIsOk() throws Exception {
        createValidator(
        "jwt:\n" +
        "  token:\n" +
        "    verification-key: |\n" +
        "      Not-Used\n" +
        "    signing-key: |\n" +
        "      Not-Used\n" +
        "    claims:\n" +
        "      exclude:\n" +
        "        - authorities\n");
        assertTrue(validator.getObject().jwt.token.verificationKey.contains("Not-Used"));
        assertTrue(validator.getObject().jwt.token.signingKey.contains("Not-Used"));
        assertTrue(validator.getObject().jwt.token.claims.exclusions.contains("authorities"));
    }

    @Test
    void invalidIssuerUriCausesException() {
        assertThatExceptionOfType(ConstraintViolationException.class).isThrownBy(() ->
                createValidator("name: uaa\nissuer.uri: notauri\n"));
    }
}
