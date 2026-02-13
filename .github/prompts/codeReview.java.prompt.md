---
agent: "true"
---

Perform a comprehensive code review of the changes between the current branch and master branch, following CloudFoundry UAA project standards:

## Core Review Areas:

1. **Null safety**: 
   - Check for proper null checks and null-safe alternatives
   - Verify Optional usage where appropriate
   - Use Objects.requireNonNull() for required parameters
   - Check @Nullable/@NonNull annotations usage
   - Avoid returning null; prefer Optional or empty collections

2. **Resource management**: 
   - Verify proper handling of AutoCloseable resources using try-with-resources
   - Check for potential memory leaks in connection pools, streams, readers
   - Verify database connections are properly closed (Spring Data JPA auto-management)
   - Check Flyway migrations are properly structured

3. **Performance optimization**: 
   - Efficient collections with proper initial capacity
   - Stream API usage and lambda optimizations
   - Unnecessary boxing/unboxing operations
   - String concatenation efficiency (StringBuilder for loops)
   - Database query optimization (N+1 queries, proper fetch strategies)
   - Caching strategy for frequently accessed data

4. **Exception handling**: 
   - Use specific exception types rather than generic ones
   - Meaningful error messages and proper logging
   - Avoid swallowed exceptions (empty catch blocks)
   - Proper use of try-with-resources for AutoCloseable resources
   - Custom exceptions for domain-specific errors
   - Proper exception propagation and error responses

5. **Code quality**: 
   - Meaningful variable and method names following Java conventions
   - Proper encapsulation (private fields with accessors)
   - Code structure and organization
   - Method complexity and single responsibility principle
   - Proper separation of concerns (controller/service/repository layers)
   - Consistent coding style (4-space indentation, 100 char line limit)

6. **Thread safety**: 
   - Race conditions and proper synchronization
   - Concurrent collections usage
   - Deadlock potential
   - ThreadLocal cleanup (IdentityZoneHolder, SecurityContextHolder)
   - Stateless service design for multi-threaded environments

7. **Security vulnerabilities**: 
   - SQL injection prevention (use JPA/Spring Data with parameterized queries)
   - Input validation and sanitization at controller boundaries
   - OAuth2/JWT token validation and expiration handling
   - Multi-zone/multi-tenant data isolation using IdentityZoneHolder
   - Role-based access control and scope enforcement
   - Sensitive data exposure in logs (passwords, tokens, PII, secrets)
   - SCIM 2.0 protocol security constraints and validation
   - SAML2 authentication security (signature validation, response validation)
   - LDAP injection prevention
   - Session fixation and CSRF protection
   - Cryptographic operations using BouncyCastle FIPS
   - XSS prevention in Thymeleaf templates
   - Proper error messages (don't leak system internals)

8. **Unit test coverage and adequacy**: 
   - Test coverage meets 80%+ target for business logic
   - Test gaps and missing edge cases (null, empty, boundary values)
   - Proper use of JUnit 5 (Jupiter) with @ExtendWith annotations
   - MockitoExtension for Mockito-based tests
   - PollutionPreventionExtension for SecurityContext/IdentityZoneHolder cleanup
   - Mocking strategies for external dependencies
   - Spring Data JPA repository mocking
   - ScimUserProvisioning, IdentityProviderProvisioning mocking
   - OAuth2 authentication context mocking
   - Controller testing with MockMvc
   - Parameterized tests (@ParameterizedTest) for multiple scenarios
   - Testability improvements (dependency injection, method decomposition)
   - AssertJ assertions for cleaner test code

9. **Java best practices**: 
   - Immutability where appropriate (final fields, classes)
   - Favor composition over inheritance
   - Use of interfaces for flexibility
   - Consistent error handling strategy
   - Proper use of Java 21 features where beneficial
   - Avoid code duplication (DRY principle)

10. **Logging**: 
    - SLF4J-based logging with Log4j2 implementation
    - Proper log levels (TRACE, DEBUG, INFO, WARN, ERROR)
    - Sufficient contextual logging for debugging
    - Include zone IDs, request IDs, user IDs (where safe)
    - No sensitive information in logs (passwords, tokens, PII)
    - Every catch block should log error-level with exception stack trace
    - Use SanitizedLogFactory for sensitive data handling
    - Structured logging for better observability

## Memory Leak Detection:
- Unclosed resources (streams, connections, readers, writers)
- Improper management of large collections
- Listener/observer registrations without deregistration
- Strongly referenced objects in static collections
- ThreadLocal variables not cleaned up (SecurityContextHolder, IdentityZoneHolder)

## Additional Review Criteria:
- **Defensive programming**: Proper parameter validation and null handling
- **Code readability**: Extract complex logic into smaller, well-named methods
- **Performance**: Collection sizing, efficient queries, proper indexing
- **Maintainability**: Clear separation of concerns, modularity
- **Documentation**: Javadoc for public APIs with @param, @return, @throws

**Important**: Do not make changes - just provide detailed analysis and recommendations.

## API Design Review:
For REST API-related code, also evaluate:

1. **Spring MVC endpoint design**: 
   - Proper use of @RestController, @Controller annotations
   - @RequestMapping, @GetMapping, @PostMapping, @PutMapping, @DeleteMapping
   - Path variable and request parameter binding
   - Proper HTTP method usage (GET for read, POST for create, PUT/PATCH for update, DELETE for delete)

2. **Response objects**: 
   - Correct HTTP status codes with ResponseEntity<T>
   - Proper use of HttpStatus constants (OK, CREATED, NO_CONTENT, BAD_REQUEST, NOT_FOUND, etc.)
   - Consistent error response format

3. **Request/Response DTOs**: 
   - Proper Jackson serialization/deserialization
   - Clear separation between domain models and DTOs
   - @JsonProperty, @JsonIgnore annotations where needed

4. **Input validation**: 
   - Jakarta Bean Validation annotations (@NotNull, @Valid, @Size, @Email, etc.)
   - Custom validators for complex validation
   - Proper validation error handling with BindingResult

5. **Error handling strategy**: 
   - @ExceptionHandler for consistent error responses
   - @ControllerAdvice for global exception handling
   - Proper HTTP status codes for different error types

6. **Documentation quality**: 
   - Comprehensive Javadoc with @param, @return, @throws
   - Clear method and class descriptions
   - API documentation (OpenAPI/Swagger annotations where applicable)

7. **Backward compatibility**: 
   - Breaking changes identification
   - Version compatibility considerations
   - Deprecation strategy

8. **Authentication/Authorization**: 
   - OAuth2/JWT token validation on protected endpoints
   - @PreAuthorize, @Secured annotations usage
   - Scope and authority checking

9. **Multi-zone/tenant context**: 
   - Proper IdentityZoneHolder usage
   - Tenant context propagation
   - Data isolation verification

## UAA-Specific Technology Review:

### Spring Boot 3.5.3 & Spring Framework 6.x
- Proper Spring Boot starter usage
- Spring MVC controller patterns
- Spring Security configuration
- Spring Data JPA repository patterns
- @Transactional annotation usage with appropriate propagation
- Dependency injection best practices (@Autowired, constructor injection)

### Spring Security 6.x
- OAuth2 authorization server configuration
- JWT token generation and validation
- OpenID Connect endpoint security
- SecurityContext management
- @PreAuthorize, @Secured method security
- CSRF protection configuration
- Session management with Spring Session JDBC

### Spring Data JPA
- Repository interface design
- Query methods naming conventions
- @Query annotations for custom queries
- Entity relationships (OneToMany, ManyToOne, ManyToMany)
- Cascade types and fetch strategies (LAZY vs EAGER)
- @Transactional boundaries
- Pagination and sorting

### Database & Flyway
- Flyway migration scripts (V{version}__{description}.sql)
- Database compatibility (PostgreSQL, MySQL, HSQLDB)
- Proper indexing for performance
- Database transaction management
- Connection pool configuration

### Multi-Zone/Tenant Architecture
- IdentityZoneHolder initialization and cleanup
- Zone context propagation across service layers
- Multi-tenant data isolation verification
- Zone-specific configuration management
- PollutionPreventionExtension usage in tests

### OAuth2 & OpenID Connect
- OAuth2 endpoint implementations (/oauth/authorize, /oauth/token)
- JWT token structure and claims
- Token validation and expiration
- Refresh token handling
- OpenID Connect endpoints (/userinfo, /token_key, /check_token)
- Client authentication and authorization
- Grant type implementations (authorization_code, client_credentials, password, etc.)

### SCIM 2.0 Protocol
- SCIM resource model compliance (User, Group, schemas)
- SCIM filtering, pagination, and sorting
- SCIM error responses and status codes
- SCIM patch operations handling
- ScimUser, ScimGroup entity design

### SAML2 Integration
- SAML2 service provider configuration
- Metadata endpoint implementation
- SAML assertion validation
- Signature verification using BouncyCastle
- SAML logout request/response handling

### LDAP Integration
- LDAP authentication configuration
- LDAP user provisioning
- LDAP query construction (avoid LDAP injection)
- Spring LDAP template usage

### Thymeleaf Templates
- Proper template structure
- Spring Security integration (sec:authorize)
- XSS prevention (automatic escaping)
- CSRF token handling
- View controller mapping

### BouncyCastle FIPS
- Cryptographic operations compliance
- Key generation and management
- Signature creation and verification
- Proper algorithm selection

### Jackson JSON Processing
- Proper use of ObjectMapper
- Custom serializers/deserializers where needed
- @JsonProperty, @JsonIgnore annotations
- Date/time serialization format consistency
- Avoid exposing sensitive fields

### StatsD Metrics
- Metrics emission for key operations
- Proper metric naming conventions
- Performance monitoring integration

### Code Quality Tools Compliance
- No SonarQube quality gate violations
- JaCoCo coverage thresholds met (80%+)
- WhiteSource security vulnerability scanning clean
- Code style consistency (4-space indent, 100 char lines)
