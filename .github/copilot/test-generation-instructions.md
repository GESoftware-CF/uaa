# Test Case Generation Instructions for GitHub Copilot

When generating test cases for this project, follow these guidelines:

## Testing Framework

- Use JUnit 5 for all new test cases
- Utilize Mockito for mocking dependencies
- Use AssertJ for fluent assertions
- Follow the Arrange-Act-Assert (AAA) pattern

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

1. **Unit Tests**
   - Test individual methods in isolation
   - Mock all dependencies
   - Focus on specific behaviors

2. **Integration Tests**
   - Test interaction between components
   - Use test containers for database or external service testing
   - Verify correct communication between layers

3. **Parameterized Tests**
   - Use `@ParameterizedTest` for multiple input variations
   - Test boundary conditions with various inputs
   - Include edge cases and special values

4. **Exception Tests**
   - Verify exceptions are thrown when expected
   - Check exception messages and types
   - Test recovery from exceptions

## Mocking Guidelines

- Only mock direct dependencies, not transitive ones
- Use strict stubbing with Mockito
- Prefer mockito-inline for mocking static methods or final classes
- Use `@Spy` for partial mocking when needed

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

- Test all API endpoints with different inputs
- Verify correct status codes and response bodies
- Include authentication/authorization tests
- Test rate limiting and error responses

## Security Testing

- Add negative tests for security (SQL injection, XSS, invalid auth).
- Verify authorization boundaries (users can’t access what they shouldn’t).
- Test secure defaults (e.g., strong TLS configs if applicable).

## Best Practices

- Keep tests independent and idempotent
- Avoid test interdependence
- Don't test trivial code (getters/setters)
- Focus on behavior, not implementation
- Use setup methods for common initialization
- Clean up resources in teardown methods