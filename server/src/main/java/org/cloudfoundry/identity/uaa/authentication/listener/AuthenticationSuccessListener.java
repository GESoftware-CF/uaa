/*
 *  Cloud Foundry
 *  Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *  <p/>
 *  This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  You may not use this product except in compliance with the License.
 *  <p/>
 *  This product includes a number of subcomponents with
 *  separate copyright notices and license terms. Your use of these
 *  subcomponents is subject to the terms and conditions of the
 *  subcomponent's license, as noted in the LICENSE file
 */

package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.AbstractUaaAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.TimeService;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;

public class AuthenticationSuccessListener
        implements ApplicationListener<AbstractUaaAuthenticationEvent>, ApplicationEventPublisherAware {

    private final ScimUserProvisioning scimUserProvisioning;
    private final TimeService timeService;
    private UserAttributeChangeEventPublisher userAttributeChangeEventPublisher;
    private ApplicationEventPublisher publisher;
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    public AuthenticationSuccessListener(ScimUserProvisioning scimUserProvisioning,
            UaaUserDatabase userDatabase,
            TimeService timeService) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.timeService = timeService;
    }

    @Autowired(required = false)
    public void setUserAttributeChangeEventPublisher(
            UserAttributeChangeEventPublisher userAttributeChangeEventPublisher) {
        this.userAttributeChangeEventPublisher = userAttributeChangeEventPublisher;
    }

    @Override
    public void onApplicationEvent(AbstractUaaAuthenticationEvent event) {
        logger.info("AuthenticationSuccessListener received event: {}", event.getClass().getSimpleName());
        if (event instanceof UserAuthenticationSuccessEvent successEvent) {
            logger.info("Processing UserAuthenticationSuccessEvent for user: {}", successEvent.getUser().getUsername());
            onApplicationEvent(successEvent, event.getIdentityZoneId());
        } else if (event instanceof IdentityProviderAuthenticationSuccessEvent passwordAuthEvent) {
            logger.info(
                    "Converting IdentityProviderAuthenticationSuccessEvent to UserAuthenticationSuccessEvent for user: {}",
                    passwordAuthEvent.getUser().getUsername());
            UserAuthenticationSuccessEvent userEvent = new UserAuthenticationSuccessEvent(
                    passwordAuthEvent.getUser(),
                    (Authentication) passwordAuthEvent.getSource(), IdentityZoneHolder.getCurrentZoneId());
            publisher.publishEvent(userEvent);
            logger.info("Published UserAuthenticationSuccessEvent for user: {}",
                    passwordAuthEvent.getUser().getUsername());
        }
    }

    protected void onApplicationEvent(UserAuthenticationSuccessEvent event, String zoneId) {
        UaaUser user = event.getUser();
        logger.info("Processing user authentication success for user: {} with origin: {}", user.getUsername(),
                user.getOrigin());
        if (user.isLegacyVerificationBehavior() && !user.isVerified()) {
            scimUserProvisioning.verifyUser(user.getId(), -1, zoneId);
        }
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        authentication.setLastLoginSuccessTime(user.getLastLogonTime());

        user.setLastLogonTime(timeService.getCurrentTimeMillis());
        scimUserProvisioning.updateLastLogonTime(user, zoneId);

        if (userAttributeChangeEventPublisher != null) {
            logger.info(
                    "UserAttributeChangeEventPublisher is available, calling publishUserAttributeChangeEventAsync for user: {}",
                    user.getUsername());
            userAttributeChangeEventPublisher.publishUserAttributeChangeEventAsync(this, user);
        } else {
            logger.warn("UserAttributeChangeEventPublisher is NULL - SNS publishing is disabled or not configured");
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }
}