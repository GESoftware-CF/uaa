# Code Review Instructions for GitHub Copilot

When reviewing code in this project, focus on these aspects and guidelines:

## Priority Concerns

1. **Correctness**: Does the code correctly implement the intended functionality?
2. **Security**: Are there any security vulnerabilities?
3. **Performance**: Are there any performance issues or inefficiencies?
4. **Maintainability**: Is the code clean, understandable, and well-structured?

## Dependency & Build Review

- Verify no unnecessary dependencies are introduced.
- Ensure dependencies are up-to-date and free of known vulnerabilities.
- Check for circular dependencies or tight coupling between modules.

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

- Ensure log levels are used correctly (INFO, WARN, ERROR, DEBUG).
- Check that logs don’t expose sensitive information.
- Confirm logging provides enough context for debugging (e.g., request IDs, user IDs where safe).

## Scalability & Extensibility

- Check that the code can handle expected growth in data/traffic.
- Look for hardcoded values that should be configurable.
- Verify new code is designed to be extensible without major rewrites.

## CI/CD & Tooling

- Verify that code builds successfully in CI without manual steps.
- Ensure static analysis tools (SonarQube, Checkstyle, SpotBugs) warnings are addressed.
- Confirm code does not reduce test coverage thresholds