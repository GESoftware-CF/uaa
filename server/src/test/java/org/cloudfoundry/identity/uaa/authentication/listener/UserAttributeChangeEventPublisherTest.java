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
        private UaaUser userBefore;
        private UaaUser userAfter;
        private String snsTopicArn = "arn:aws:sns:us-east-1:123456789012:uaa-events";

        @BeforeEach
        void setUp() {
                publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn, false);

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
                lenient().when(mockSnsService.publishAsync(anyString(), anyString(), any(MessageBuilder.class), any()))
                                .thenReturn(CompletableFuture.completedFuture(null));
        }

        @Test
        void testPublishUserAttributeChangeEventAsync_success() {
                // Arrange - User with changed email and previousUser set
                UaaUser userWithChangedEmail = userAfter.modifyEmail("newemail@example.com")
                                .withPreviousUser(userBefore);

                // Act
                publisher.publishUserAttributeChangeEventAsync(userWithChangedEmail);

                // Allow async execution to complete
                try {
                        Thread.sleep(100);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                eq(snsTopicArn),
                                eq("UAA User Update Event"),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testPublishUserAttributeChangeEventAsync_withNoChanges_shouldNotPublish() {
                // Arrange - User with no changes except lastLogonTime (no previousUser set
                // means compare with itself)
                UaaUser userWithOnlyLogonTimeChange = userAfter;

                // Act
                publisher.publishUserAttributeChangeEventAsync(userWithOnlyLogonTimeChange);

                // Allow async execution to complete
                try {
                        Thread.sleep(200);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - SNS should still be called, but message builder will return null if
                // no changes
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                anyString(),
                                anyString(),
                                any(MessageBuilder.class),
                                any());
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
                UaaUser after = new UaaUser(afterPrototype)
                                .withPreviousUser(before);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after);

                // Allow async execution
                try {
                        Thread.sleep(100);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - Verify SNS was called
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                eq(snsTopicArn),
                                eq("UAA User Update Event"),
                                any(MessageBuilder.class),
                                any());
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
                UaaUser after = new UaaUser(afterPrototype)
                                .withPreviousUser(before);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after);

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
                                any());
        }

        @Test
        void testPublishUserAttributeChangeEventAsync_withNullUsers_shouldThrowNPE() {
                // Act & Assert - should throw NullPointerException when null user is passed
                assertThrows(NullPointerException.class, () -> {
                        publisher.publishUserAttributeChangeEventAsync(null);
                });

                // Verify that SNS was never called
                verify(mockSnsService, never()).publishAsync(
                                anyString(),
                                anyString(),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testPublishUserAttributeChangeEventAsync_whenSnsThrowsException_shouldNotCrash() {
                // Arrange
                when(mockSnsService.publishAsync(anyString(), anyString(), any(MessageBuilder.class), any()))
                                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("SNS error")));

                UaaUser userWithPrevious = userAfter.withPreviousUser(userBefore);

                // Act - should not throw exception
                assertDoesNotThrow(() -> {
                        publisher.publishUserAttributeChangeEventAsync(userWithPrevious);
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
                                any());
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
                                .withLastLogonSuccess(null); // First time login

                UaaUserPrototype afterPrototype = beforePrototype
                                .withLastLogonSuccess(System.currentTimeMillis());

                UaaUser before = new UaaUser(beforePrototype);
                UaaUser after = new UaaUser(afterPrototype)
                                .withPreviousUser(before);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after);

                // Allow async execution
                try {
                        Thread.sleep(100);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                eq(snsTopicArn),
                                eq("UAA User Update Event"),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testPublishUserAttributeChangeEventAsync_asyncBehavior() {
                // This test verifies that the method is truly async
                // by checking that it returns immediately without blocking

                // Arrange
                long startTime = System.currentTimeMillis();
                UaaUser userWithPrevious = userAfter.withPreviousUser(userBefore);

                // Act
                publisher.publishUserAttributeChangeEventAsync(userWithPrevious);

                // Assert - method should return quickly (within 50ms)
                long endTime = System.currentTimeMillis();
                assertTrue((endTime - startTime) < 50,
                                "Method should return quickly due to async execution");

                // Verify the SNS call is made (might take longer due to async)
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                anyString(),
                                anyString(),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testPublishUserAttributeChangeEventAsync_withDifferentOrigins() {
                // Test with SAML origin
                UaaUser samlUser = new UaaUser(new UaaUserPrototype()
                                .withId("saml-user")
                                .withUsername("saml.user")
                                .withEmail("saml@example.com")
                                .withOrigin(OriginKeys.SAML))
                                .withPreviousUser(userBefore);

                publisher.publishUserAttributeChangeEventAsync(samlUser);

                // Test with OIDC origin
                UaaUser oidcUser = new UaaUser(new UaaUserPrototype()
                                .withId("oidc-user")
                                .withUsername("oidc.user")
                                .withEmail("oidc@example.com")
                                .withOrigin(OriginKeys.OIDC10))
                                .withPreviousUser(userBefore);

                publisher.publishUserAttributeChangeEventAsync(oidcUser);

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
                                any());
        }

        @Test
        void testFilterUaaOrigin_whenFalse_shouldPublishForUaaOrigin() {
                // Arrange - filterUaaOrigin is false (default)
                publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn, false);

                UaaUserPrototype beforePrototype = new UaaUserPrototype()
                                .withId("uaa-user-1")
                                .withUsername("uaa.user")
                                .withEmail("uaa@example.com")
                                .withGivenName("UAA")
                                .withFamilyName("User")
                                .withOrigin(OriginKeys.UAA)
                                .withLastLogonSuccess(1000L);

                UaaUserPrototype afterPrototype = beforePrototype
                                .withEmail("uaa.new@example.com")
                                .withLastLogonSuccess(2000L);

                UaaUser before = new UaaUser(beforePrototype);
                UaaUser after = new UaaUser(afterPrototype)
                                .withPreviousUser(before);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after);

                // Allow async execution
                try {
                        Thread.sleep(100);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - SNS should be called even for UAA origin
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                eq(snsTopicArn),
                                eq("UAA User Update Event"),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testFilterUaaOrigin_whenTrue_shouldSkipUaaOrigin() {
                // Arrange - filterUaaOrigin is true
                publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn, true);

                UaaUserPrototype beforePrototype = new UaaUserPrototype()
                                .withId("uaa-user-2")
                                .withUsername("uaa.filtered")
                                .withEmail("filtered@example.com")
                                .withGivenName("Filtered")
                                .withFamilyName("User")
                                .withOrigin(OriginKeys.UAA)
                                .withLastLogonSuccess(1000L);

                UaaUserPrototype afterPrototype = beforePrototype
                                .withEmail("filtered.new@example.com")
                                .withLastLogonSuccess(2000L);

                UaaUser before = new UaaUser(beforePrototype);
                UaaUser after = new UaaUser(afterPrototype)
                                .withPreviousUser(before);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after);

                // Allow async execution
                try {
                        Thread.sleep(100);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - SNS should NOT be called because UAA origin is filtered
                verify(mockSnsService, never()).publishAsync(
                                any(),
                                any(),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testFilterUaaOrigin_whenTrue_shouldPublishForNonUaaOrigin() {
                // Arrange - filterUaaOrigin is true, but user has SAML origin
                publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn, true);

                UaaUserPrototype beforePrototype = new UaaUserPrototype()
                                .withId("saml-user-3")
                                .withUsername("saml.user")
                                .withEmail("saml@example.com")
                                .withGivenName("SAML")
                                .withFamilyName("User")
                                .withOrigin(OriginKeys.SAML)
                                .withLastLogonSuccess(1000L);

                UaaUserPrototype afterPrototype = beforePrototype
                                .withEmail("saml.new@example.com")
                                .withLastLogonSuccess(2000L);

                UaaUser before = new UaaUser(beforePrototype);
                UaaUser after = new UaaUser(afterPrototype)
                                .withPreviousUser(before);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after);

                // Allow async execution
                try {
                        Thread.sleep(100);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - SNS should be called for SAML origin even with filter enabled
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                eq(snsTopicArn),
                                eq("UAA User Update Event"),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testFilterUaaOrigin_whenTrue_shouldPublishForOidcOrigin() {
                // Arrange - filterUaaOrigin is true, but user has OIDC origin
                publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn, true);

                UaaUserPrototype beforePrototype = new UaaUserPrototype()
                                .withId("oidc-user-4")
                                .withUsername("oidc.user")
                                .withEmail("oidc@example.com")
                                .withGivenName("OIDC")
                                .withFamilyName("User")
                                .withOrigin(OriginKeys.OIDC10)
                                .withLastLogonSuccess(1000L);

                UaaUserPrototype afterPrototype = beforePrototype
                                .withEmail("oidc.new@example.com")
                                .withLastLogonSuccess(2000L);

                UaaUser before = new UaaUser(beforePrototype);
                UaaUser after = new UaaUser(afterPrototype)
                                .withPreviousUser(before);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after);

                // Allow async execution
                try {
                        Thread.sleep(100);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - SNS should be called for OIDC origin even with filter enabled
                verify(mockSnsService, timeout(1000).times(1)).publishAsync(
                                eq(snsTopicArn),
                                eq("UAA User Update Event"),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testFilterUaaOrigin_whenTrue_multipleUaaUsers_shouldSkipAll() {
                // Arrange - filterUaaOrigin is true
                publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn, true);

                // Create multiple UAA origin users
                UaaUserPrototype proto1 = new UaaUserPrototype()
                                .withId("uaa-user-5")
                                .withUsername("uaa.user1")
                                .withEmail("user1@example.com")
                                .withOrigin(OriginKeys.UAA)
                                .withLastLogonSuccess(1000L);

                UaaUserPrototype proto2 = new UaaUserPrototype()
                                .withId("uaa-user-6")
                                .withUsername("uaa.user2")
                                .withEmail("user2@example.com")
                                .withOrigin(OriginKeys.UAA)
                                .withLastLogonSuccess(1000L);

                UaaUser before1 = new UaaUser(proto1);
                UaaUser after1 = new UaaUser(proto1.withEmail("user1.new@example.com").withLastLogonSuccess(2000L))
                                .withPreviousUser(before1);

                UaaUser before2 = new UaaUser(proto2);
                UaaUser after2 = new UaaUser(proto2.withEmail("user2.new@example.com").withLastLogonSuccess(2000L))
                                .withPreviousUser(before2);

                // Act
                publisher.publishUserAttributeChangeEventAsync(after1);
                publisher.publishUserAttributeChangeEventAsync(after2);

                // Allow async execution
                try {
                        Thread.sleep(200);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - SNS should NOT be called because all users have UAA origin and are
                // filtered
                verify(mockSnsService, never()).publishAsync(
                                any(),
                                any(),
                                any(MessageBuilder.class),
                                any());
        }

        @Test
        void testFilterUaaOrigin_whenTrue_mixedOrigins_shouldOnlySkipUaa() {
                // Arrange - filterUaaOrigin is true, test with mixed origins
                publisher = new UserAttributeChangeEventPublisher(mockSnsService, snsTopicArn, true);

                // UAA origin user
                UaaUserPrototype uaaProto = new UaaUserPrototype()
                                .withId("uaa-user-7")
                                .withUsername("uaa.mixed")
                                .withEmail("uaa@example.com")
                                .withOrigin(OriginKeys.UAA)
                                .withLastLogonSuccess(1000L);

                // SAML origin user
                UaaUserPrototype samlProto = new UaaUserPrototype()
                                .withId("saml-user-7")
                                .withUsername("saml.mixed")
                                .withEmail("saml@example.com")
                                .withOrigin(OriginKeys.SAML)
                                .withLastLogonSuccess(1000L);

                // LDAP origin user
                UaaUserPrototype ldapProto = new UaaUserPrototype()
                                .withId("ldap-user-7")
                                .withUsername("ldap.mixed")
                                .withEmail("ldap@example.com")
                                .withOrigin(OriginKeys.LDAP)
                                .withLastLogonSuccess(1000L);

                UaaUser uaaBefore = new UaaUser(uaaProto);
                UaaUser uaaAfter = new UaaUser(uaaProto.withEmail("uaa.new@example.com"))
                                .withPreviousUser(uaaBefore);

                UaaUser samlBefore = new UaaUser(samlProto);
                UaaUser samlAfter = new UaaUser(samlProto.withEmail("saml.new@example.com"))
                                .withPreviousUser(samlBefore);

                UaaUser ldapBefore = new UaaUser(ldapProto);
                UaaUser ldapAfter = new UaaUser(ldapProto.withEmail("ldap.new@example.com"))
                                .withPreviousUser(ldapBefore);

                // Act - publish events for all three users
                publisher.publishUserAttributeChangeEventAsync(uaaAfter);
                publisher.publishUserAttributeChangeEventAsync(samlAfter);
                publisher.publishUserAttributeChangeEventAsync(ldapAfter);

                // Allow async execution
                try {
                        Thread.sleep(300);
                } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                }

                // Assert - SNS should be called 2 times (UAA filtered, SAML and LDAP published)
                verify(mockSnsService, timeout(1000).times(2)).publishAsync(
                                eq(snsTopicArn),
                                eq("UAA User Update Event"),
                                any(MessageBuilder.class),
                                any());
        }
}
