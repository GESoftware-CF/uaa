# Code Generation Instructions for GitHub Copilot

When generating code in this project, follow these standards and practices:

## General Principles

- Follow Java best practices and standard conventions
- Write self-documenting code with meaningful variable/method names
- Include proper Javadoc comments for public methods and classes
- Prefer composition over inheritance
- Use type safety and strong typing where possible
- Aim for immutability when appropriate
- Provide clear, descriptive error messages
- Follow clean code principles, Java coding standards, and SOLID principles.
- Use Spring idioms and annotations appropriately.
- Ensure modularity, separation of concerns, and testability.
- Apply relevant design patterns where beneficial.
- Code should be maintainable and extensible for long-term evolution.

## Core Technologies & Compliance Tooling 

- Follow dependencies.gradle for dependencies and their versions
- Build Quality: JaCoCo, SpotBugs, PMD, Sonar, CycloneDX, WhiteSource

## Version Control & Branching 

- Default branches : `master` (production) and `develop` (integration). Feature development via topic branches
- Branch naming: `feature/<ADO-ID>-short-desc`, `bugfix/<ADO-ID>`, `hotfix/<ADO-ID>`, `release/<version>`
- Base feature branches off `develop`, merge back to `develop` via Pull Request
- Hotfixes branch from `master`, merge to both `master` and `develop`
- Commit messages: Conventional format with ADO work item reference (`<ADO-ID>: concise description`)
- Pull Requests: include rationale, test evidence (coverage improvements), note any dependency/version changes
- Avoid committing build artifacts, local settings (respect, `.gitignore`)
- Jenkins CI/CD automatically triggers on `develop` and `master` branches for builds and deployments

## Documentation & Comments
- Document public APIs clearly with examples if needed.
- Add TODO/FIXME comments sparingly, only when necessary.
- Keep comments up-to-date with code changes.

## Coding Style

- Use 4-space indentation
- Follow Google Java Style Guide for formatting
- Use camelCase for methods and variables, PascalCase for classes
- Limit line length to 100 characters
- Group related code blocks with a single blank line between them
- Follow checkstyle rules configured in the project

## Build & Dependency Management

- Follow semantic versioning for internal modules/libraries
- Avoid unnecessary external dependencies
- Keep dependencies up-to-date and check for known vulnerabilities

## API & Integration Guidelines (if applicable)

- For REST APIs: follow RESTful principles and use standard HTTP status codes
- Provide clear request/response models and avoid leaking internal details
- Ensure backward compatibility when changing public interfaces

## Error Handling

- Use specific exception types rather than generic ones
- Include proper exception handling with try-catch blocks
- Utilize try-with-resources for AutoCloseable resources
- Avoid swallowing exceptions (empty catch blocks)
- Add meaningful context to exception messages

## Concurrency & Thread Safety

- Always document thread-safety expectations of classes (immutable, synchronized, etc.).
- Prefer java.util.concurrent utilities over manual thread management.
- Avoid shared mutable state whenever possible.

## Null Safety

- Use Optional<T> for values that might be absent
- Add null checks for parameters in public methods
- Use Objects.requireNonNull() for validating required parameters
- Add @Nullable/@NonNull annotations where appropriate

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

- Use SLF4J-based logging
- Ensure that enough logging is present in the code for debugging and monitoring purposes
- Use trace level logs for informational and debug level for very important messages and error level for exceptions and errors