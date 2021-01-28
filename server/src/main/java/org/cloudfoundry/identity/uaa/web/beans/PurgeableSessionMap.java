package org.cloudfoundry.identity.uaa.web.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.session.ExpiringSession;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.stream.Collectors.toList;

@Component
class PurgeableSessionMap extends ConcurrentHashMap<String, ExpiringSession> {
    private final static Logger logger = LoggerFactory.getLogger(PurgeableSessionMap.class);

    @Scheduled(fixedDelayString = "${servlet-session-purge-delay:900000}")
    public void purge() {
        List<ExpiringSession> expired = expired();
        expired.forEach(s -> remove(s.getId()));
        logger.debug(String.format("Purged %s sessions", expired.size()));
    }

    public List<ExpiringSession> expired() {
        return values().stream().filter(ExpiringSession::isExpired).collect(toList());
    }
}
