package org.cloudfoundry.identity.uaa.web.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

@Configuration
@EnableSpringHttpSession
@EnableScheduling
public class UaaMemorySessionConfig extends UaaSessionConfig {

    private final static Logger logger = LoggerFactory.getLogger(UaaMemorySessionConfig.class);

    @Bean
    public MapSessionRepository sessionRepository(
            final @Value("${servlet.idle-timeout:1800}") int idleTimeout,
            @Autowired PurgeableSessionMap purgeableSessionMap
    ) {
        MapSessionRepository sessionRepository = new MapSessionRepository(purgeableSessionMap);
        sessionRepository.setDefaultMaxInactiveInterval(idleTimeout);
        return sessionRepository;
    }

    @Autowired
    void log() {
        logger.info("Using memory session configuration");
    }
}