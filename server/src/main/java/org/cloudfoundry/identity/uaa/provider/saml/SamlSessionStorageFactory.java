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

package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.storage.SAMLMessageStorageFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class SamlSessionStorageFactory implements SAMLMessageStorageFactory {

    private static Log logger = LogFactory.getLog(SamlSessionStorageFactory.class);

    public static final String SAML_REQUEST_DATA = SamlMessageStorage.class.getName() + ".saml.requests";

    @Override
    public synchronized SAMLMessageStorage getMessageStorage(HttpServletRequest request) {
        if (IdentityZoneHolder.get().getConfig().getSamlConfig().isDisableInResponseToCheck()) {
            //add the ability to disable inResponseTo check
            //https://docs.spring.io/spring-security-saml/docs/current/reference/html/chapter-troubleshooting.html
            return null;
        }
        String sessionId = "";
        HttpSession testSession = request.getSession(false);
        if (testSession != null) {
            sessionId = testSession.getId();
        }
        logger.debug("MARCH9DEBUG: SAMLSessionStorageFactory.getMessageStorage() if session exists id is: -> " + sessionId);
        HttpSession session = request.getSession(true);
        logger.debug("MARCH9DEBUG: SAMLSessionStorageFactory.getMessageStorage() end session used is: -> " + session.getId());
        if (session.getAttribute(SAML_REQUEST_DATA) == null) {
            logger.debug("MARCH9DEBUG: SAML Request Data is null, session SAML_REQUEST_DATA attribute is new SAMLMessageStorage()");
            session.setAttribute(SAML_REQUEST_DATA, new SamlMessageStorage());
        } else {
            logger.debug("MARCH9DEBUG: SAML Request Data is not null" + session.getAttribute(SAML_REQUEST_DATA));
        }
        logger.debug("Returning SAML message factory for session ID:"+session.getId());
        return (SAMLMessageStorage) session.getAttribute(SAML_REQUEST_DATA);
    }
}
