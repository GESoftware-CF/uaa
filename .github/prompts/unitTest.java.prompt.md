---
agent: "true"
---

Generate unit tests for this Java code following CloudFoundry UAA project standards:

1. **Test Structure**
   - Use JUnit 5 (Jupiter) - this is the standard across the project
   - Use @ExtendWith(MockitoExtension.class) for Mockito-based unit tests
   - Use @ExtendWith(PollutionPreventionExtension.class) for tests that need isolation (e.g., SecurityContext, IdentityZoneHolder cleanup)
   - Name tests: descriptive method names like `changePasswordWithNoCurrentPasswordOrUsername()` or `shouldExpectedBehaviorWhenCondition()`
   - Follow AAA pattern (Arrange-Act-Assert)
   - Use @BeforeEach for test setup, @AfterEach for cleanup
   - Use @Nested classes to group related tests
   - Use @ParameterizedTest with @EnumSource, @ValueSource, or @MethodSource for data-driven tests

2. **Coverage Requirements (80%+ target)**
   - Test all public methods
   - Cover happy path scenarios
   - Test error conditions and exceptions
   - Validate input edge cases (null, empty, boundary values)
   - Test business logic and validation rules
   - Include integration tests using MockMvc for controller endpoints

3. **Security Testing**
   - Test OAuth2/JWT token validation and unauthorized access scenarios
   - Test OpenID Connect endpoint behaviors
   - Validate input sanitization against SQL injection, XSS, and other attacks
   - Test multi-zone/multi-tenant data isolation (users can't access other zone's data)
   - Verify role-based authorization and scope enforcement
   - Test SCIM 2.0 protocol security constraints
   - Test SAML2 authentication flows and validation
   - Verify sensitive data (passwords, tokens, PII) is never logged or exposed
   - Test session management and CSRF protection

4. **Mocking Strategy**
   - Mock external dependencies with @Mock (Mockito - version managed by Spring Boot)
   - Use @InjectMocks for class under test (or manual construction in @BeforeEach)
   - Use mock() directly for simple mocks in setup methods
   - Mock Spring Data JPA repositories and services
   - Mock ScimUserProvisioning, IdentityProviderProvisioning, IdentityZoneProvisioning
   - Mock PasswordValidator, UaaPasswordPolicyValidator
   - Mock OAuth2 authentication context, SecurityContextHolder, IdentityZoneHolder
   - Mock external REST calls using RestTemplate or WebClient
   - Use lenient() for Mockito strict stubbing warnings when needed
   - Verify interactions with verify() and ArgumentCaptor
   - For static utilities, consider refactoring or use mockito-inline

5. **Assertion Strategy**
   - Use AssertJ assertions: assertThat(), assertThatThrownBy(), assertThatExceptionOfType()
   - Use JUnit 5 assertions: assertEquals(), assertNotNull(), assertTrue() when appropriate
   - For exceptions: assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> ...)
   - Verify mock interactions: verify(mock).method(arguments)
   - Use ArgumentCaptor for complex verification

6. **UAA Project Specifics**
   - Test OAuth2 endpoints (/oauth/authorize, /oauth/token) behavior
   - Test OpenID Connect endpoints (/userinfo, /token_key, /check_token)
   - Test SCIM 2.0 endpoints for users, groups, identity providers
   - Test SAML2 service provider integration
   - Test LDAP authentication and user provisioning
   - Test multi-zone/tenant isolation using IdentityZoneHolder
   - Test Flyway database migrations (if applicable)
   - Mock Spring Security context and authentication objects
   - Test Thymeleaf view rendering (for UI controllers)
   - Test session management with Spring Session JDBC
   - Handle BouncyCastle FIPS cryptographic operations
   - Test StatsD metrics emission
   - Use MockHttpServletRequest and MockHttpServletResponse for servlet testing
   - Use MockMvc for controller integration tests

7. **Test Data**
   - Create meaningful test data builders or factory methods
   - Use parameterized tests (@ParameterizedTest) for multiple scenarios
   - Define test constants at class level
   - Use AlphanumericRandomValueStringGenerator for random test data
   - Create realistic ScimUser, IdentityProvider, IdentityZone test objects
   - Mock UaaUser, Authentication objects with appropriate authorities/scopes

8. **Test Isolation**
   - Use @ExtendWith(PollutionPreventionExtension.class) to clean up:
     - SecurityContextHolder
     - IdentityZoneHolder
     - ThreadLocal state
   - Clear context in @BeforeEach or @AfterEach when needed
   - Use @Nested classes for logical test grouping

**Generate tests that are maintainable, focused, and achieve the 80%+ coverage target while following CloudFoundry UAA standards.**
