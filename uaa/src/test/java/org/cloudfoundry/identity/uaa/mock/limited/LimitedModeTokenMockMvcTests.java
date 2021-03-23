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

package org.cloudfoundry.identity.uaa.mock.limited;

import org.cloudfoundry.identity.uaa.mock.token.TokenMvcMockTests;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@LimitedMode
public class LimitedModeTokenMockMvcTests extends TokenMvcMockTests {
    // To set Predix UAA limited/degraded mode, use environment variable instead of StatusFile

    @Test
    void check_token_while_limited() throws Exception {
        BaseClientDetails client = setUpClients(generator.generate().toLowerCase(),
                                                "uaa.resource,clients.read",
                                                "",
                                                "client_credentials",
                                                true);
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, client.getClientId(), SECRET, null, null, true);
        mockMvc.perform(
            post("/check_token")
                .param("token", token)
                .header(AUTHORIZATION,
                        "Basic " + new String(Base64.encode((client.getClientId() + ":" + SECRET).getBytes())))
        )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.scope").value(containsInAnyOrder("clients.read", "uaa.resource")))
            .andExpect(jsonPath("$.client_id").value(client.getClientId()))
            .andExpect(jsonPath("$.jti").value(token));
    }
}
