package org.cloudfoundry.identity.uaa.web.beans;

import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.junit.Rule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
@ExtendWith(PollutionPreventionExtension.class)
class UaaSessionConfigTest {

    @Mock
    private ConditionContext mockConditionContext;

    @Mock
    private Environment mockEnvironment;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @BeforeEach
    void setUp() {
        MockitoAnnotations.initMocks(this);
        when(mockConditionContext.getEnvironment()).thenReturn(mockEnvironment);
    }

    @Test
    void whenDatabaseIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("database");

        assertFalse(new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null));
        assertTrue(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null));
    }

    @Test
    void whenMemoryIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("memory");

        assertTrue(new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null));
        assertFalse(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null));
    }

    @Test
    void whenFoobarIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("foobar");

        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("foobar is not a valid argument for servlet.session-store. Please choose memory or " +
                                        "database.");

        new UaaMemorySessionConfig.MemoryConfigured();
        new UaaJdbcSessionConfig.DatabaseConfigured();
    }
}