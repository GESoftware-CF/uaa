package org.cloudfoundry.identity.uaa.web.beans;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.session.ExpiringSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PurgeableSessionMapTest {
    private static final String SESSION_ID = "id";
    private PurgeableSessionMap sessions;

    @BeforeEach
    void setUp() {
        sessions = new PurgeableSessionMap();
    }

    @Test
    void doesNotDeleteActiveSessions() {
        sessions.put(SESSION_ID, createSession(SESSION_ID, false));

        sessions.purge();
        assertEquals(1, sessions.size());
        assertTrue(sessions.containsKey(SESSION_ID));
    }

    @Test
    void deletesActiveSessions() {
        sessions.put(SESSION_ID, createSession(SESSION_ID, true));

        sessions.purge();
        assertEquals(0, sessions.size());
    }

    private ExpiringSession createSession(String id, boolean expired) {
        ExpiringSession session = mock(ExpiringSession.class);
        when(session.getId()).thenReturn(id);
        when(session.isExpired()).thenReturn(expired);

        return session;
    }
}