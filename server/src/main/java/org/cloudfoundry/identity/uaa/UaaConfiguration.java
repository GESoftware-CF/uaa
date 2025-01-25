package org.cloudfoundry.identity.uaa;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(UaaProperties.class)
class UaaConfiguration {
}
