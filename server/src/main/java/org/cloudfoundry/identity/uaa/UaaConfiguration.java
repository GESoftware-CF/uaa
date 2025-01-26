package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(UaaProperties.class)
class UaaConfiguration {

    @Bean
    KeyInfoService keyInfoService(UaaProperties uaaProperties) {
        return new KeyInfoService(uaaProperties.getUrl());
    }

}
