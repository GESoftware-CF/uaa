package org.cloudfoundry.identity.uaa.web.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nonnull;

@Configuration
@Conditional(UaaMemorySessionConfig.MemoryConfigured.class)
@EnableSpringHttpSession
public class UaaMemorySessionConfig extends UaaSessionConfig {

    private final static Logger logger = LoggerFactory.getLogger(UaaMemorySessionConfig.class);

    public static class MemoryConfigured implements Condition {
        @Override
        public boolean matches(@Nonnull ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
            String sessionStore = getSessionStore(context.getEnvironment());
            validateSessionStore(sessionStore);
            return MEMORY_SESSION_STORE_TYPE.equals(sessionStore);
        }
    }

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