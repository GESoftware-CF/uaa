package org.cloudfoundry.identity.uaa.provider.saml;

import com.ge.iam.sns.service.SnsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration for UAA-to-SNS integration.
 * This class enables component scanning of the SNS service beans from iam-k8s-utils module.
 */
@Configuration
@ComponentScan(basePackages = { "com.ge.iam.sns" })
public class UaaSnsConfig {

    private static final Logger logger = LoggerFactory.getLogger(UaaSnsConfig.class);

    public UaaSnsConfig() {
        logger.info("UaaSnsConfig initialized - scanning com.ge.iam.sns for SNS service beans");
    }
}
