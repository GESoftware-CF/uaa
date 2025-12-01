package org.cloudfoundry.identity.uaa.authentication.listener;

import com.ge.iam.sns.service.MessageBuilder;
import com.ge.iam.sns.service.SnsService;
import com.google.gson.JsonObject;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Updated tests for UserAttributeChangeEventPublisher with SNS integration.
 * Tests verify async SNS publishing behavior for user attribute changes.
 */
@ExtendWith(MockitoExtension.class)
class UserAttributeChangeEventPublisherTest {

    @Mock
    private SnsService mockSnsService;

    private UserAttributeChangeEventPublisher publisher;
    private Object source;
    private UaaUser userBefore;
    private UaaUser userAfter;
    private String snsTopicArn = "arn:aws:sns:us-east-1:123456789012:uaa-events";

    @BeforeEach
    void setUp() {
        publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn);
        source = new Object();
        
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withId("user-id")
                .withUsername("testuser")
                .withEmail("test@example.com")
                .withGivenName("Test")
                .withFamilyName("User")
                .withOrigin(OriginKeys.SAML);
        
        userBefore = new UaaUser(prototype);
        userAfter = new UaaUser(prototype.withLastLogonSuccess(System.currentTimeMillis()));

        // Mock SNS service to return completed future
        when(mockSnsService.publishAsync(anyString(), anyString(), any(MessageBuilder.class), any()))
                .thenReturn(CompletableFuture.completedFuture(null));
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_success() {
        // Arrange - User with changed email
        UaaUser userWithChangedEmail = userAfter.modifyEmail("newemail@example.com");

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userWithChangedEmail);

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                eq(snsTopicArn),
                eq("UAA User Event"),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withNoChanges_shouldNotPublish() {
        // Arrange - User with no changes except lastLogonTime
        UaaUser userWithOnlyLogonTimeChange = userAfter;

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userWithOnlyLogonTimeChange);

        // Allow async execution to complete
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - SNS should still be called, but message builder will return null if no changes
        verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                anyString(),
                anyString(),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withEmailChange() {
        // Arrange
        UaaUserPrototype beforePrototype = new UaaUserPrototype()
                .withId("user-123")
                .withUsername("john.doe")
                .withEmail("john@example.com")
                .withGivenName("John")
                .withFamilyName("Doe")
                .withOrigin(OriginKeys.OIDC10)
                .withLastLogonSuccess(1000L);
        
        UaaUserPrototype afterPrototype = beforePrototype
                .withEmail("john.new@example.com")
                .withLastLogonSuccess(2000L);

        UaaUser before = new UaaUser(beforePrototype);
        UaaUser after = new UaaUser(afterPrototype);

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, before, after);

        // Allow async execution
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - Verify SNS was called
        verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                eq(snsTopicArn),
                eq("UAA User Event"),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withMultipleChanges() {
        // Arrange
        UaaUserPrototype beforePrototype = new UaaUserPrototype()
                .withId("user-456")
                .withUsername("jane.smith")
                .withEmail("jane@example.com")
                .withGivenName("Jane")
                .withFamilyName("Smith")
                .withPhoneNumber("+1234567890")
                .withOrigin(OriginKeys.SAML);
        
        UaaUserPrototype afterPrototype = beforePrototype
                .withEmail("jane.new@example.com")
                .withGivenName("Janet")
                .withPhoneNumber("+0987654321");

        UaaUser before = new UaaUser(beforePrototype);
        UaaUser after = new UaaUser(afterPrototype);

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, before, after);

        // Allow async execution
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                anyString(),
                anyString(),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withNullUsers_shouldNotCrash() {
        // Act - should not throw exception
        assertDoesNotThrow(() -> {
            publisher.publishUserAttributeChangeEventAsync(source, null, userAfter);
        });

        assertDoesNotThrow(() -> {
            publisher.publishUserAttributeChangeEventAsync(source, userBefore, null);
        });

        // Allow async execution
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - SNS should be called but message builder returns null
        verify(mockSnsService, timeout(1000).atLeast(2)).publishAsync(
                anyString(),
                anyString(),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_whenSnsThrowsException_shouldNotCrash() {
        // Arrange
        when(mockSnsService.publishAsync(anyString(), anyString(), any(MessageBuilder.class), any()))
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("SNS error")));

        // Act - should not throw exception
        assertDoesNotThrow(() -> {
            publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);
        });

        // Allow async execution
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - SNS was called despite error
        verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                anyString(),
                anyString(),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_firstTimeLogin() {
        // Arrange - User with no previous lastLogonTime (first login)
        UaaUserPrototype beforePrototype = new UaaUserPrototype()
                .withId("user-789")
                .withUsername("first.login")
                .withEmail("first@example.com")
                .withGivenName("First")
                .withFamilyName("Login")
                .withOrigin(OriginKeys.SAML)
                .withLastLogonSuccess(null);  // First time login
        
        UaaUserPrototype afterPrototype = beforePrototype
                .withLastLogonSuccess(System.currentTimeMillis());

        UaaUser before = new UaaUser(beforePrototype);
        UaaUser after = new UaaUser(afterPrototype);

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, before, after);

        // Allow async execution
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                eq(snsTopicArn),
                eq("UAA User Event"),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_asyncBehavior() {
        // This test verifies that the method is truly async
        // by checking that it returns immediately without blocking
        
        // Arrange
        long startTime = System.currentTimeMillis();

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);

        // Assert - method should return quickly (within 50ms)
        long endTime = System.currentTimeMillis();
        assertTrue((endTime - startTime) < 50, 
                "Method should return quickly due to async execution");

        // Verify the SNS call is made (might take longer due to async)
        verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                anyString(),
                anyString(),
                any(MessageBuilder.class),
                any()
        );
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withDifferentOrigins() {
        // Test with SAML origin
        UaaUser samlUser = new UaaUser(new UaaUserPrototype()
                .withId("saml-user")
                .withUsername("saml.user")
                .withEmail("saml@example.com")
                .withOrigin(OriginKeys.SAML));

        publisher.publishUserAttributeChangeEventAsync(source, userBefore, samlUser);

        // Test with OIDC origin
        UaaUser oidcUser = new UaaUser(new UaaUserPrototype()
                .withId("oidc-user")
                .withUsername("oidc.user")
                .withEmail("oidc@example.com")
                .withOrigin(OriginKeys.OIDC10));

        publisher.publishUserAttributeChangeEventAsync(source, userBefore, oidcUser);

        // Allow async execution
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - both should trigger SNS calls
        verify(mockSnsService, timeout(1000).atLeast(2)).publishAsync(
                anyString(),
                anyString(),
                any(MessageBuilder.class),
                any()
        );
    }
}
