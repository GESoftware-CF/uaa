/*
 * ****************************************************************************
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
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;

public class KeyInfoService {
    private static final Logger logger = LoggerFactory.getLogger(KeyInfoService.class);

    private final String uaaBaseURL;

    public KeyInfoService(String uaaBaseURL) {
        this.uaaBaseURL = uaaBaseURL;
    }

    public KeyInfo getKey(String keyId, String sigAlg) {
        return getKeys(sigAlg).get(keyId);
    }

    public KeyInfo getKey(String keyId) {
        return getKeys().get(keyId);
    }

    public Map<String, KeyInfo> getKeys() {
        return getKeys(null);
    }

    public Map<String, KeyInfo> getKeys(String sigAlg) {
        long startTime = System.currentTimeMillis();
        logger.info("[KeyInfoService#getKeys] START - resolving signing keys (sigAlg={})", sigAlg);

        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config == null || config.getTokenPolicy().getKeys() == null
                || config.getTokenPolicy().getKeys().isEmpty()) {
            logger.info("[KeyInfoService#getKeys] Zone config is null or has no keys; falling back to UAA zone config");
            config = IdentityZoneHolder.getUaaZone().getConfig();
        }

        Map<String, KeyInfo> keys = new HashMap<>();
        for (Map.Entry<String, TokenPolicy.KeyInformation> entry : config.getTokenPolicy().getKeys().entrySet()) {
            String keyId = entry.getKey();
            String signingKey = entry.getValue().getSigningKey();
            logger.info("[KeyInfoService#getKeys] Building KeyInfo for keyId='{}', signingKey='{}'", keyId, signingKey);
            KeyInfo keyInfo = KeyInfoBuilder.build(keyId, signingKey,
                    addSubdomainToUrl(uaaBaseURL, IdentityZoneHolder.get().getSubdomain()),
                    sigAlg != null ? sigAlg : entry.getValue().getSigningAlg(),
                    entry.getValue().getSigningCert());
            keys.put(keyId, keyInfo);
        }

        if (keys.isEmpty()) {
            logger.info("[KeyInfoService#getKeys] No keys found; using legacy token key");
            keys.put(LegacyTokenKey.LEGACY_TOKEN_KEY_ID, LegacyTokenKey.getLegacyTokenKeyInfo());
        }

        long elapsed = System.currentTimeMillis() - startTime;
        logger.info("[KeyInfoService#getKeys] END - resolved {} key(s) in {} ms", keys.size(), elapsed);
        return keys;
    }

    public KeyInfo getActiveKey() {
        long startTime = System.currentTimeMillis();
        logger.info("[KeyInfoService#getActiveKey] START - resolving active signing key");
        String activeKeyId = getActiveKeyId();
        Map<String, KeyInfo> keys = getKeys();
        KeyInfo activeKey = keys.get(activeKeyId);
        long elapsed = System.currentTimeMillis() - startTime;
        if (activeKey != null) {
            logger.info(
                    "[KeyInfoService#getActiveKey] END - activeKeyId='{}', verifierKey='{}', algorithm='{}', time={} ms",
                    activeKeyId, activeKey.verifierKey(), activeKey.algorithm(), elapsed);
        } else {
            logger.info("[KeyInfoService#getActiveKey] END - activeKeyId='{}' not found in keys map, time={} ms",
                    activeKeyId, elapsed);
        }
        return activeKey;
    }

    private String getActiveKeyId() {
        long startTime = System.currentTimeMillis();
        logger.info("[KeyInfoService#getActiveKeyId] START - resolving activeKeyId");

        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config == null) {
            String fallbackKeyId = IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
            logger.info(
                    "[KeyInfoService#getActiveKeyId] END - config null, falling back to UAA zone activeKeyId='{}', time={} ms",
                    fallbackKeyId, System.currentTimeMillis() - startTime);
            return fallbackKeyId;
        }
        String activeKeyId = config.getTokenPolicy().getActiveKeyId();
        logger.info("[KeyInfoService#getActiveKeyId] activeKeyId from current zone='{}'", activeKeyId);

        Map<String, KeyInfo> keys;
        if (!StringUtils.hasText(activeKeyId) && (keys = getKeys()).size() == 1) {
            activeKeyId = keys.keySet().stream().findAny().get();
            logger.info("[KeyInfoService#getActiveKeyId] Single key found; using keyId='{}'", activeKeyId);
        }

        if (!StringUtils.hasText(activeKeyId)) {
            activeKeyId = IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
            logger.info("[KeyInfoService#getActiveKeyId] Falling back to UAA zone activeKeyId='{}'", activeKeyId);
        }

        if (!StringUtils.hasText(activeKeyId)) {
            activeKeyId = LegacyTokenKey.LEGACY_TOKEN_KEY_ID;
            logger.info("[KeyInfoService#getActiveKeyId] Falling back to LEGACY_TOKEN_KEY_ID");
        }

        logger.info("[KeyInfoService#getActiveKeyId] END - resolved activeKeyId='{}', time={} ms",
                activeKeyId, System.currentTimeMillis() - startTime);
        return activeKeyId;
    }

    public String getTokenEndpointUrl() throws URISyntaxException {
        return UaaTokenUtils.constructTokenEndpointUrl(uaaBaseURL, IdentityZoneHolder.get());
    }
}
