# GitHub Copilot Instructions

This document consolidates all GitHub Copilot instructions for code generation, code review, and test generation in this project.

## Project Overview

Multi-module Gradle project delivering CloudFoundry User Account and Authentication (UAA) Server. This is a Java-based Spring Boot 3.5.3 application providing multi-tenant identity management, OAuth2 authentication, and SSO capabilities. Key modules include:
- **uaa** (primary Spring Boot WAR application, default port: 8080)
- **server** (core CloudFoundry Identity Server JAR with business logic)
- **model** (domain models and DTOs)
- **metrics-data** (metrics and monitoring data models)
- **statsd** and **statsd-lib** (StatsD integration for metrics)
- **zone-service** (zone/tenant management service)
- **iam-k8s-utils** (Kubernetes utilities for IAM)
- **docs** (project documentation)

Key concerns: multi-tenant identity management, OAuth2/OpenID Connect provider, user authentication and authorization, SAML2 service provider, LDAP integration, SCIM user provisioning, Spring Security, database persistence (PostgreSQL/MySQL/HSQLDB via Flyway migrations), audit logging, containerization, code quality & compliance (JaCoCo, Sonar, WhiteSource).

## Module Descriptions

### Core Service Modules

**uaa** - Primary UAA web application
- Spring Boot 3.5.3 WAR application written in Java
- REST endpoints for OAuth2 authentication (/oauth/authorize, /oauth/token)
- User login interface and token grant approval
- OpenID Connect endpoints (/userinfo, /token_key, /check_token)
- SCIM user provisioning endpoints
- Thymeleaf-based web UI
- PostgreSQL/MySQL/HSQLDB support with Flyway for database migrations
- Multi-tenant/zone context management
- Default port: 8080
- Gradle build with Tomcat deployment

**server** - Core CloudFoundry Identity Server JAR
- Core business logic and service layer
- User authentication and authorization services
- SAML2 service provider integration
- LDAP integration support
- Spring Security configuration
- Database access and transaction management
- Session management with Spring Session JDBC
- Shared across UAA web application

**model** - Domain models and DTOs
- User, client, and identity provider models
- SCIM resource representations
- Request/response DTOs
- Shared data structures

### Metrics & Monitoring Modules

**metrics-data** - Metrics and monitoring data models
- Metrics data structures
- Performance monitoring utilities

**statsd** and **statsd-lib** - StatsD integration
- StatsD client for metrics collection
- Integration with monitoring systems
- Performance metrics tracking

### Management Modules

**zone-service** - Zone/tenant management service
- Java-based zone management functionality
- Handles tenant isolation and zone operations
- Integrates with UAA server for multi-tenancy

**iam-k8s-utils** - Kubernetes utilities for IAM
- Kubernetes client integration
- IAM-related Kubernetes operations
- Deployment and configuration utilities

### Documentation Module

**docs** - Project documentation
- API documentation
- Configuration guides
- Integration documentation

## General Principles

- Follow Java best practices and standard conventions
- Write self-documenting code with meaningful variable/method names
- Include proper Javadoc comments for public methods and classes
- Prefer composition over inheritance
- Use type safety and strong typing
- Aim for immutability when appropriate (use final for variables and classes where possible)
- Provide clear, descriptive error messages
- Follow clean code principles, Java coding standards, and SOLID principles
- Use Spring idioms and annotations appropriately
- Ensure modularity, separation of concerns, and testability
- Apply relevant design patterns where beneficial
- Code should be maintainable and extensible for long-term evolution

## Core Technologies & Compliance Tooling

- Java 21, Gradle 8.x+ (with wrapper)
- Spring Boot 3.5.3 (Spring Framework 6.x)
- Spring Security 6.x, OAuth2 + JWT + OpenID Connect
- Spring Session JDBC (for distributed session management)
- Database: PostgreSQL 42.7.7, MySQL (MariaDB 2.7.12), HSQLDB 2.7.4 (tests only), Flyway 7.15.0 for migrations
- SAML2: OpenSAML 4.0.1, Spring Security SAML2 Service Provider
- LDAP: Apache Directory Server, Spring LDAP Core, Unbounded LDAP SDK
- Testing: JUnit Jupiter (JUnit 5), Mockito, Spring Boot Test, Selenium 4.34.0, RestDocs
- API Documentation: OpenAPI/Swagger (via annotations)
- Web UI: Thymeleaf 3.x with Spring Security integration
- Observability: SLF4J, Log4j2, StatsD client for metrics
- HTTP Client: Apache HttpComponents
- Build Quality: JaCoCo 0.8.13, Sonar, WhiteSource
- Containerization: Docker (Cargo Gradle Plugin, Tomcat 10.1.43)
- Security: BouncyCastle FIPS (2.1.x series for crypto operations)
- AWS Integration: Spring Cloud AWS Secrets Manager (optional)

## Environment Details

- **JDK**: 21 (ensure `JAVA_HOME` points to JDK 21)
- **Build Tool**: Gradle 8.x+ (use provided wrapper: `./gradlew`)
- **OS**: Development on macOS (primary), Linux (CI/CD), Windows (supported)
- **Container Runtime**: Docker (for integration tests and local development)
- **psql**: PostgreSQL command-line tool (for database operations)
- **Encoding**: UTF-8
- **IDE**: IntelliJ IDEA (recommended) with Java support enabled
- **Environment Variables**: 
  - ARTIFACTORY_CREDENTIALS_USR and ARTIFACTORY_CREDENTIALS_PSW (for GE Artifactory access)
  - PROXY_HOST and PROXY_PORT (optional, for corporate proxy)
- **Port Requirements**: 8080 (UAA server), 5432 (PostgreSQL), 3306 (MySQL), 389 (LDAP for tests)

## Dependency & Plugin Version Alignment

**Key Version Properties (ensure consistency across modules):**
- Java: 21
- Gradle: 8.x+ (use wrapper)
- spring-boot: 3.5.3
- spring-framework: 6.x (managed by Spring Boot BOM)
- spring-security: 6.x (managed by Spring Boot BOM)
- postgresql: 42.7.7
- mariadb: 2.7.12
- hsqldb: 2.7.4 (tests only)
- flyway: 7.15.0
- opensaml: 4.0.1
- bouncycastle-fips: 2.1.x series (bc-fips 2.1.0, bcpkix-fips 2.1.9, bctls-fips 2.1.20)
- selenium: 4.34.0 (integration tests only)
- jackson: 2.19.2
- guava: 33.4.8-jre
- tomcat: 10.1.43
- jacoco: 0.8.13
- junit-jupiter: 5.x (managed by Spring Boot BOM)
- mockito: 5.x (managed by Spring Boot BOM)

**Guidelines:**
- Use Gradle wrapper (`./gradlew`) for all builds to ensure consistent Gradle version
- Leverage Spring Boot BOM (Bill of Materials) for consistent dependency versions
- Keep all Spring Boot starters at identical versions to avoid compatibility issues
- Use Flyway (not Liquibase) for database migrations
- BouncyCastle FIPS libraries are required for cryptographic operations
- Ensure Artifactory credentials are set: ARTIFACTORY_CREDENTIALS_USR and ARTIFACTORY_CREDENTIALS_PSW environment variables
- Dependencies are fetched from GE Artifactory: `https://dig-grid-artifactory.apps.ge.com/artifactory/pgog-fss-iam-uaa-mvn-virtual`
- Tomcat 10.1.43 is used for Cargo plugin containerization during build and integration tests

## Version Control & Branching

- Default branch: `master` (primary branch for CloudFoundry UAA)
- Branch naming: `feature/<short-desc>`, `bugfix/<ticket-id>`, `hotfix/<ticket-id>`, `release/<version>`
- Feature branches: create from `master`, merge back to `master` via Pull Request
- Commit messages: Conventional format with concise description
- Pull Requests: include rationale, test evidence (coverage improvements), note any dependency/version changes
- Avoid committing build artifacts, local settings (respect `.gitignore`)
- CI/CD automatically triggers on `master` branch for builds and deployments
- Version managed in `gradle.properties`: current version is 78.2.0

## Build & Test Instructions

**Standard full build (all modules, run tests, generate coverage & reports):**
```bash
./gradlew clean build
```

**Run UAA server locally:**
```bash
./gradlew run
# UAA will be available at http://localhost:8080/uaa
```

**Build specific module:**
```bash
./gradlew :cloudfoundry-identity-server:build
# or
./gradlew :cloudfoundry-identity-uaa:build
```

**Run all tests:**
```bash
./gradlew test
```

**Run specific test class in a module:**
```bash
./gradlew :cloudfoundry-identity-server:test --tests "YourTestClassName"
```

**Run integration tests:**
```bash
./gradlew integrationTest
```

**Generate coverage reports:**
```bash
./gradlew jacocoRootReport
# Coverage reports will be in build/reports/jacoco/jacocoRootReport/
```

**Run Sonar analysis:**
```bash
./gradlew sonarqube
```

**Common build issues:**
- Ensure JAVA_HOME points to JDK 21
- Port conflicts: If port 8080 (UAA server) is in use, stop other services or change the port with `-Pport=<port>`
- Missing dependencies: Ensure Artifactory credentials are set (ARTIFACTORY_CREDENTIALS_USR and ARTIFACTORY_CREDENTIALS_PSW)
- Module-specific test failures: Use specific module task like `:server:test`
- Increase Gradle memory for large builds: `GRADLE_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m"`
- For dependency conflicts, run `./gradlew dependencies` to identify issues
- Clean build directory if experiencing caching issues: `./gradlew clean`

---

# Code Generation Guidelines

## Coding Style

- Use 4-space indentation
- Follow Google Java Style Guide for formatting
- Use camelCase for methods and variables, PascalCase for classes
- Limit line length to 100 characters
- Group related code blocks with a single blank line between them
- Follow checkstyle rules configured in the project

## Documentation & Comments

- Document public APIs clearly with examples if needed
- Use Javadoc for Java classes and methods
- Add TODO/FIXME comments sparingly, only when necessary
- Keep comments up-to-date with code changes
- Include @param, @return, and @throws documentation for public methods

## Build & Dependency Management

- Follow semantic versioning for internal modules/libraries
- Avoid unnecessary external dependencies
- Keep dependencies up-to-date and check for known vulnerabilities

## API & Integration Guidelines

- For REST APIs: follow RESTful principles using Spring REST annotations (@RestController, @GetMapping, @PostMapping, etc.)
- Use standard HTTP status codes with ResponseEntity objects
- Provide clear request/response models and avoid leaking internal details
- Ensure backward compatibility when changing public interfaces
- Leverage Jackson for JSON serialization/deserialization
- Use Swagger/OpenAPI for API documentation where appropriate
- OAuth2 endpoints follow standard specifications
- SCIM endpoints follow SCIM 2.0 specification

## Error Handling

- Use specific exception types rather than generic ones
- Include proper exception handling with try-catch blocks
- Utilize try-with-resources for AutoCloseable resources
- Avoid swallowing exceptions (empty catch blocks)
- Add meaningful context to exception messages

## Concurrency & Thread Safety

- Always document thread-safety expectations of classes (immutable, synchronized, etc.)
- Prefer java.util.concurrent utilities over manual thread management
- Avoid shared mutable state whenever possible

## Null Safety

- Use Optional<T> for values that might be absent
- Add null checks for parameters in public methods
- Use Objects.requireNonNull() for validating required parameters
- Add @Nullable/@NonNull annotations where appropriate (e.g., from javax.annotation or Spring annotations)
- Document null handling expectations in Javadoc
- Avoid returning null from methods; prefer Optional or empty collections

## Performance Considerations

- Use StringBuilder for string concatenation in loops
- Initialize collections with appropriate initial capacity when size is known
- Use efficient data structures for the specific use case
- Consider thread safety in shared objects
- Use streams and lambdas where they improve readability

## Testing Considerations

- Write code that is easily testable
- Use dependency injection to facilitate testing
- Avoid static methods for business logic
- Separate business logic from I/O operations

## Security Guidelines

- Sanitize all user input
- Use parameterized queries for database operations
- Never log sensitive information
- Use secure cryptographic algorithms and practices
- Validate all inputs at system boundaries

## Logging Guidelines

- Use SLF4J-based logging (Logback implementation)
- Ensure that enough logging is present in the code for debugging and monitoring purposes
- Use TRACE level for detailed flow information, DEBUG for important diagnostic messages, INFO for business events, WARN for recoverable issues, and ERROR for exceptions
- Never log sensitive information (passwords, tokens, PII) - use appropriate redaction/masking
- Include contextual information (tenant IDs, request IDs, user IDs where safe) for troubleshooting in multi-tenant environments

## Security & Compliance Guidelines

- Do not embed credentials, tokens, or sensitive data in code or configuration files
- Use environment variables or secure secret management for sensitive configuration
- Keep dependency versions updated to remediate CVEs; coordinate major framework upgrades
- Validate input payloads via Jakarta Validation annotations and custom validators
- Use parameterized queries and avoid string concatenation for dynamic SQL
- Apply principle of least privilege for service accounts and database access
- Remove deprecated libraries in favor of actively maintained alternatives

---

# Code Review Guidelines

## Priority Concerns

1. **Correctness**: Does the code correctly implement the intended functionality?
2. **Security**: Are there any security vulnerabilities?
3. **Performance**: Are there any performance issues or inefficiencies?
4. **Maintainability**: Is the code clean, understandable, and well-structured?

## Dependency & Build Review

- Verify no unnecessary dependencies are introduced
- Ensure dependencies are up-to-date and free of known vulnerabilities
- Check for circular dependencies or tight coupling between modules

## Null Safety Review

- Check that all objects are null-checked before access
- Verify that Optional is used appropriately
- Look for potential NullPointerExceptions
- Ensure defensive null handling is implemented

## Resource Management Review

- Verify all resources (connections, streams, etc.) are properly closed
- Check for potential memory leaks
- Confirm proper use of try-with-resources
- Look for resource cleanup in error cases

## Thread Safety Review

- Identify potential race conditions
- Check for proper synchronization
- Ensure thread-safe collections are used where needed
- Look for deadlock possibilities

## Performance Review

- Identify inefficient algorithms or data structures
- Check for N+1 query problems in database operations
- Review collection sizing and initialization
- Look for unnecessary object creation
- Check for inefficient string operations

## Exception Handling Review

- Verify exceptions are handled at appropriate levels
- Check for swallowed exceptions
- Ensure exceptions include meaningful context
- Confirm that resources are released when exceptions occur

## Code Style and Maintainability

- Verify consistent formatting and naming conventions
- Check for code duplication
- Look for methods that are too long or complex
- Ensure proper encapsulation
- Verify code follows SOLID principles

## Test Coverage Review

- Check that all edge cases are tested
- Verify happy paths and error paths are covered
- Look for missing test cases
- Ensure mocks are used appropriately

## Security Review

- Check for input validation
- Verify proper authentication and authorization
- Look for SQL injection possibilities
- Check for proper handling of sensitive data
- Verify secure communication practices

## API Design Review

- Check for consistent API design
- Verify backward compatibility
- Ensure proper documentation
- Look for clear method signatures and parameter naming

## Logging Review

- Ensure log levels are used correctly (INFO, WARN, ERROR, DEBUG)
- Check that logs don't expose sensitive information
- Confirm logging provides enough context for debugging (e.g., request IDs, user IDs where safe)

## Scalability & Extensibility

- Check that the code can handle expected growth in data/traffic
- Look for hardcoded values that should be configurable
- Verify new code is designed to be extensible without major rewrites

## CI/CD & Tooling

- Verify that code builds successfully in CI without manual steps
- Ensure static analysis tools (SonarQube, Checkstyle, SpotBugs) warnings are addressed
- Confirm code does not reduce test coverage thresholds

---

# Test Generation Guidelines

## Testing Framework

- Use JUnit 5 (Jupiter) for all test cases (consistent across project)
- Utilize Mockito for mocking dependencies
- Use AssertJ or standard JUnit assertions
- Follow the Arrange-Act-Assert (AAA) pattern
- Use Spring Boot Test support for integration tests

## Test Structure

- Name test methods descriptively using format: `should[ExpectedBehavior]When[StateUnderTest]`
- Group related tests in nested classes using `@Nested`
- Use `@DisplayName` for human-readable test descriptions
- Keep test methods focused on a single assertion or concept

## Test Coverage Requirements

- Aim for 80%+ line coverage for all business logic
- Cover all edge cases and boundary conditions
- Include both positive and negative test cases
- Test exception paths and error handling

## Types of Tests to Include

### 1. Unit Tests
- Test individual methods in isolation
- Mock all dependencies
- Focus on specific behaviors

### 2. Integration Tests
- Test interaction between components
- Use test containers for database or external service testing
- Verify correct communication between layers

### 3. Parameterized Tests
- Use `@ParameterizedTest` for multiple input variations
- Test boundary conditions with various inputs
- Include edge cases and special values

### 4. Exception Tests
- Verify exceptions are thrown when expected
- Check exception messages and types
- Test recovery from exceptions

## Mocking Guidelines

- Only mock direct dependencies, not transitive ones
- Use strict stubbing with Mockito
- Prefer mockito-inline for mocking static methods or final classes
- Use `@Spy` for partial mocking when needed
- Use modern Mockito features for all new test code

## Test Data

- Use test data builders or factory methods
- Create reusable test fixtures for common objects
- Use meaningful test data that represents real-world scenarios
- Avoid magic numbers/strings, use named constants

## Database Testing

- Use an in-memory database for unit tests
- Set up test data in @Before methods or use `@SQL` annotations
- Clean up database after tests
- Use transactions to isolate tests

## API Testing

- Test all REST endpoints with different inputs
- Verify correct status codes and response bodies using ResponseEntity
- Include authentication/authorization tests (OAuth2/JWT token validation)
- Test error responses and exception handlers
- Use @SpringBootTest with TestRestTemplate or WebTestClient for integration tests
- For unit testing controllers, use @WebMvcTest with MockMvc

## Security Testing

- Add negative tests for security (SQL injection, XSS, invalid auth)
- Verify authorization boundaries (users can't access what they shouldn't)
- Test secure defaults (e.g., strong TLS configs if applicable)

## Test Best Practices

- Keep tests independent and idempotent
- Avoid test interdependence
- Don't test trivial code (getters/setters)
- Focus on behavior, not implementation
- Use setup methods for common initialization
- Clean up resources in teardown methods

---

# Runtime Configuration & Troubleshooting

## Runtime Configuration

**Service Port:**
- UAA runs on port 8080 by default (configurable with `-Pport=<port>`)
- Accessible at `http://localhost:8080/uaa`

**Profiles:**
- Default: For local development with containerized services (PostgreSQL, MySQL, HSQLDB)
- Test profiles can be configured via environment variables or system properties
- Environment-specific configurations can be managed via `uaa.yml`

**Required Configuration:**
- PostgreSQL: host=localhost, port=5432 (for production-like testing)
- MySQL: host=localhost, port=3306 (alternative to PostgreSQL)
- HSQLDB: in-memory database for unit tests
- Artifactory credentials: ARTIFACTORY_CREDENTIALS_USR and ARTIFACTORY_CREDENTIALS_PSW environment variables

## Common Issues & Resolutions

| Issue | Symptom | Resolution |
|-------|---------|------------|
| Port conflicts | Build fails with port already in use | Ensure port 8080 is available. Use `-Pport=<port>` to specify alternate port. |
| Java version issues | Compilation errors or runtime issues | Verify JAVA_HOME points to JDK 21. Use `java -version` to confirm. |
| Build memory issues | OutOfMemoryError during build | Increase Gradle memory: `GRADLE_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m"` |
| Test failures | Tests fail to start DB | Ensure Docker is running and ports 5432/3306 are available for database tests. |
| Dependency resolution failures | Build fails with dependency errors | Run `./gradlew dependencies` to identify conflicts. Use `./gradlew clean` and retry. |
| Sonar coverage < threshold | Quality gate failure | Add/expand unit tests; ensure JaCoCo not skipped; run `./gradlew jacocoRootReport` |
| Spring Boot version conflicts | ClassNotFoundException or NoSuchMethodError | Ensure all Spring Boot starters use identical versions; check for version overrides in child modules |
| Artifactory authentication | Build fails with 401 Unauthorized | Set environment variables ARTIFACTORY_CREDENTIALS_USR and ARTIFACTORY_CREDENTIALS_PSW |
| Flyway migration failures | Database schema issues | Check Flyway changelog files and ensure database is accessible with correct credentials |
| Cargo tests fail | Integration tests fail to start | Check that `cargo.tests.run` property is set correctly. Verify Tomcat can start on configured port. |

## Tooling & IDE Setup

**Recommended IDE:** IntelliJ IDEA (Ultimate) or VS Code with Java extensions

**Required Plugins:**
- Gradle integration
- Java language support

**Optional IDE Plugins:**
- SonarLint for code quality checks
- JaCoCo for coverage visualization
- Docker plugin for container management

---

# Quick Reference Commands

**Full build with tests:**
```bash
./gradlew clean build
```

**Run UAA server locally:**
```bash
./gradlew run
# Access at http://localhost:8080/uaa
```

**Build specific module:**
```bash
./gradlew :cloudfoundry-identity-server:build
# Example: ./gradlew :cloudfoundry-identity-uaa:build
```

**Run tests only:**
```bash
./gradlew test
```

**Run specific test class in a module:**
```bash
./gradlew :cloudfoundry-identity-server:test --tests "YourTestClassName"
# Example: ./gradlew :server:test --tests "UserServiceTest"
```

**Run specific test method:**
```bash
./gradlew :server:test --tests "YourTestClassName.testMethodName"
```

**Run integration tests:**
```bash
./gradlew integrationTest
```

**Generate coverage reports:**
```bash
./gradlew jacocoRootReport
# Reports in build/reports/jacoco/jacocoRootReport/
```

**Check for dependency updates:**
```bash
./gradlew dependencyUpdates
```

**Analyze dependency tree for conflicts:**
```bash
./gradlew dependencies --configuration runtimeClasspath
```

**Sonar analysis:**
```bash
./gradlew sonarqube
```

---

# How Copilot Should Use This Context

## Code Generation Principles

When generating code or fixes:
- For Kotlin code: use idiomatic Kotlin patterns (data classes, extension functions, nullable types, default parameters)
- For new REST endpoints: use Spring REST annotations (@RestController, @GetMapping, @PostMapping, etc.), add request/response DTOs with validation, and provide tests with `@SpringBootTest`. Include negative validation cases
- Enforce null-safety and validation (e.g., `@NotNull`, `@Size`, `@Valid` in Java; nullable types in Kotlin) consistent with existing patterns
- Provide unit tests that maintain meaningful coverage (avoid trivial tests that only call getters/setters). Use data-driven test cases where appropriate
- For Kotlin: leverage data classes instead of Lombok or manual getters/setters
- If adding configuration properties, externalize via `application.properties` and create a `@ConfigurationProperties` class with validation
- Use JUnit 5 Jupiter consistently across all modules
- For database operations: use Liquibase for schema changes, QueryDSL for type-safe queries
- Ensure compatibility with Docker/Podman containerized dependencies (PostgreSQL, Redis)

## Framework-Specific Guidelines

**Spring Boot:**
- Use Spring Boot 3.4.6 patterns and annotations
- For REST APIs, use Spring REST annotations (@RestController, @GetMapping, @PostMapping, etc.)
- Use `@Service`, `@Repository`, `@Component` appropriately for layered architecture
- Implement proper exception handling with Spring `@ControllerAdvice` and `@ExceptionHandler`
- Leverage Spring Security for OAuth2/JWT authentication

**Kotlin:**
- Use data classes for DTOs and entity models where appropriate
- Leverage extension functions for utility operations
- Use nullable types (Type?) instead of Optional<T> in Kotlin
- Prefer immutable collections and val over var
- Use when expressions instead of switch/if-else chains

**JPA/Database:**
- Use standard JPA annotations and patterns
- Implement proper entity relationships with cascade and fetch strategies
- Use `@Transactional` appropriately with proper propagation and isolation levels
- Prefer repository pattern with Spring Data JPA
- Use Liquibase for database schema migrations
- Use QueryDSL for type-safe queries

**Security:**
- Implement OAuth2/JWT security patterns consistent with Spring Security 6.4.6
- Validate all inputs at controller boundaries
- Never log sensitive information (passwords, tokens, PII)

**Testing:**
- Use JUnit 5 (Jupiter) consistently across all modules
- Mock dependencies with Mockito 5.15.2
- Use Mockito-Kotlin for Kotlin-friendly mocking DSL
- Use `@SpringBootTest` for integration tests, `@WebMvcTest` for controller unit tests
- For REST endpoint testing, use `@SpringBootTest` with TestRestTemplate or WebTestClient
- Follow Arrange-Act-Assert pattern consistently

## Code Quality Expectations

- Generate code that passes Checkstyle analysis (Java) and ktlint/detekt analysis (Kotlin)
- Ensure generated code maintains or improves JaCoCo coverage metrics
- Include proper Javadoc for Java public APIs and KDoc for Kotlin public APIs with `@param`, `@return`, `@throws` documentation
- Use meaningful variable and method names that are self-documenting
- Handle exceptions appropriately - don't swallow exceptions or use generic Exception types

## Multi-Module Considerations

- Respect module boundaries and dependencies
- Don't introduce circular dependencies between modules
- Use proper Gradle dependency configurations (implementation, testImplementation, runtimeOnly)
- Consider which module new code belongs in based on separation of concerns:
  - **uaa**: Web layer, controllers, UI
  - **server**: Business logic, services, security
  - **model**: Domain models, DTOs
  - **zone-service**: Zone/tenant management
  - **metrics-data**: Metrics models
  - **statsd/statsd-lib**: Metrics collection
