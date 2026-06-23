# Java Code Review Guidelines with GitHub Copilot

Use these prompt instructions to guide GitHub Copilot in improving your Java code for null safety, performance, and maintainability.

## 1. Combined Prompts for Full Review

### 1.1. Comprehensive Java Review (Mandatory)

```
Perform a comprehensive review of this Java code, focusing on:
1. Null safety (null checks, Optional usage)
2. Resource management (closing streams, connections)
3. Performance optimization (efficient collections, stream usage)
4. Exception handling (specific exceptions, proper propagation)
5. Code quality (naming, structure, maintainability)
6. Thread safety (if applicable)
7. Security vulnerabilities (SQL injection, input validation, sensitive data exposure)
8. Unit test coverage and adequacy (test gaps, edge cases, mocking needs)
9. Adherence to Java best practices
10. Ensure that enough logging is present in the code for debugging and monitoring purposes
11. Use trace level logs for informational and debug level for very important messages and error level for exceptions and errors
12. Donot make changes - just give the details
```

### 1.2. API Design Review

```
Review this Java API design and suggest improvements for:
1. Interface design and method signatures
2. Error handling and exception strategy
3. Documentation quality (Javadoc)
4. Backward compatibility considerations
5. Builder pattern or fluent API where appropriate
6. Parameter validation
```

## 2. Null Safety

### 2.1. Null Pointer Checks

```
Analyze this Java method for potential NullPointerExceptions. Add null checks for all objects before method invocations and suggest using Optional where appropriate.
```

Place the cursor inside the method and enter the prompt in GitHub Copilot Chat. Alternatively, specify the method name explicitly:

```
Ensure all objects and method calls in the processUserData method are checked for null to prevent NullPointerException.
```

### 2.2. Safe Dereferencing After Null Check

```
Review this Java code and verify that all objects are properly null-checked before access. Suggest using null-safe alternatives like Optional, Objects.requireNonNull, or the Elvis operator where appropriate.
```

### 2.3. Defensive Null Handling

```
Refactor this code to use defensive null handling techniques like Optional<T>, Objects.requireNonNull(), or Objects.nonNull() instead of manual null checks.
```

## 3. Resource Management

### 3.1. AutoCloseable Resources

```
Check this Java code for proper handling of AutoCloseable resources. Ensure all resources (like streams, connections, readers, writers) are properly closed using try-with-resources.
```

### 3.2. Memory Leaks

```
Review this Java code for potential memory leaks, focusing on:
1. Unclosed resources (streams, connections, etc.)
2. Improper management of large collections
3. Inefficient use of string concatenation
4. Listener/observer registrations without corresponding deregistration
5. Strongly referenced objects in static collections
```

## 4. Performance Optimization

### 4.1. Collection Efficiency

```
Analyze the collection usage in this Java code. Suggest performance improvements by:
1. Using appropriate collection types for the operations performed
2. Optimizing operations with proper initial capacity
3. Identifying unnecessary boxing/unboxing operations
4. Using Stream API efficiently
```

### 4.2. Concurrent Code Review

```
Review this Java code for thread safety issues and concurrency problems, including:
1. Race conditions
2. Proper synchronization
3. Efficient use of concurrent collections
4. Thread-safe singleton implementation
5. Deadlock potential
```

### 4.3. Streams and Lambdas

```
Optimize this Java code by leveraging streams and lambdas where appropriate. Identify areas where imperative loops can be replaced with declarative stream operations.
```

## 5. Code Quality

### 5.1. Readability & Maintainability

```
Refactor this Java code to improve readability and maintainability by:
1. Using meaningful variable and method names
2. Extracting complex logic into smaller, well-named methods
3. Following standard Java naming conventions
4. Improving code structure and organization
```

### 5.2. Best Practices

```
Review this Java code for adherence to best practices, including:
1. Proper encapsulation (private fields with accessors)
2. Immutability where appropriate
3. Favor composition over inheritance
4. Use of interfaces for flexibility
5. Consistent error handling strategy
```

### 5.3. Exception Handling

```
Analyze the exception handling in this Java code. Suggest improvements for:
1. Using specific exception types rather than generic ones
2. Adding meaningful error messages
3. Proper logging of exceptions
4. Avoiding swallowed exceptions
5. Using try-with-resources for AutoCloseable resources
```

## 6. Testing

### 6.1. Unit Tests and Coverage

```
Review this Java code and suggest:
1. Areas where unit tests should be added or improved
2. Edge cases that should be tested
3. Mocking strategies for external dependencies
4. How to test private methods indirectly
5. Potential uses for parameterized tests
```

### 6.2. Testability

```
Refactor this Java code to improve testability by:
1. Reducing dependencies through dependency injection
2. Breaking down complex methods
3. Separating business logic from I/O operations
4. Making methods more deterministic
```

## 7. Security

### 7.1. Security Vulnerabilities

```
Analyze this Java code for potential security issues, including:
1. SQL injection vulnerabilities
2. Improper input validation
3. Insecure cryptographic implementations
4. Sensitive data exposure
5. Unsafe deserialization
```

## How to Use These Guidelines

1. Select the most relevant prompt(s) for your code review needs
2. Place your cursor in the method or class you want to review
3. Open GitHub Copilot Chat and paste the prompt
4. Review Copilot's suggestions and apply them as appropriate
5. Combine prompts for more comprehensive reviews