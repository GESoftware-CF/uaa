package org.cloudfoundry.identity.uaa.provider.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

import java.lang.reflect.Constructor;

/**
 * Configuration for UAA-to-SNS integration.
 * This class enables component scanning of the SNS service beans from
 * iam-k8s-utils module
 * and creates the UserAttributeChangeEventPublisher bean when SNS is enabled.
 */
@Configuration
@ComponentScan(basePackages = { "com.ge.iam.sns" })
public class UaaSnsConfig {

    private static final Logger logger = LoggerFactory.getLogger(UaaSnsConfig.class);

    public UaaSnsConfig() {
        logger.info("UaaSnsConfig initialized - scanning com.ge.iam.sns for SNS service beans");
    }
}