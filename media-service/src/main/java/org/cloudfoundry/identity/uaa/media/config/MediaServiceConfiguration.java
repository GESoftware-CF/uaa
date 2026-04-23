package org.cloudfoundry.identity.uaa.media.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for the media service module.
 * Activated only when background-image.enabled=true (default).
 */
@Configuration
@ConditionalOnProperty(
    prefix = "background-image",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@ComponentScan("org.cloudfoundry.identity.uaa.media")
@EnableConfigurationProperties(BackgroundImageProperties.class)
public class MediaServiceConfiguration {
    // Bean definitions auto-discovered via @Component scanning
}
