# GitHub Copilot Instructions for Code Tasks

This document outlines how to use GitHub Copilot with custom instructions for different coding tasks.

## How to Use These Instructions

### 1. In GitHub Copilot Chat

When using GitHub Copilot Chat, you can reference these instructions by using special prompts:

**For Code Generation:**
```
Follow our code generation standards from .github/copilot/code-generation-instructions.md to create [describe what you need].
```

**For Code Review:**
```
Review this code following our guidelines in .github/copilot/code-review-instructions.md with special attention to [specific concern].
```

**For Test Generation:**
```
Generate unit tests according to our test standards in .github/copilot/test-generation-instructions.md for this [class/method].
```

### 2. Using Inline Comments

You can add special comment markers before asking Copilot to generate code:

```java
// @copilot-instruction: Follow our Java coding standards with proper null checks and exception handling
// Generate a method to process user data
```

### 3. Setting Up for Your Team

1. All team members should clone this repository including the `.github/copilot` directory
2. Review the instruction files to understand the standards
3. Encourage consistent use of the prompts in daily work

## Custom Instructions Overview

We've created three specialized instruction sets:

1. **Code Generation Instructions** - Standards for writing new code
2. **Code Review Instructions** - Guidelines for reviewing existing code
3. **Test Generation Instructions** - Requirements for creating tests

## Examples

### Example 1: Generating a User Service

```
Follow our code generation standards from .github/copilot/code-generation-instructions.md to create a UserService class that handles user registration, validation, and persisting to a database. Ensure proper null safety and resource management.
```

### Example 2: Reviewing Authentication Logic

```
Review this authentication code following our guidelines in .github/copilot/code-review-instructions.md with special attention to security vulnerabilities and edge cases.
```

### Example 3: Creating Tests for API Endpoints

```
Generate unit tests according to our test standards in .github/copilot/test-generation-instructions.md for this REST controller handling user management operations. Include tests for error conditions and validation failures.
```