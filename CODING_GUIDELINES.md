# Coding Guidelines for Relayer Utils

This document outlines the coding guidelines for contributing to Relayer Utils. Following these guidelines will help maintain a consistent and high-quality codebase.

## 1. Code Formatting

- **Tool**: Use `rustfmt` to automatically format your code. Ensure that all code is formatted before committing.
- **Indentation**: Use 4 spaces per indentation level. Do not use tabs.
- **Line Length**: Aim to keep lines under 100 characters, but it's not a strict rule. Use your judgment to ensure readability.
- **Imports**: Group imports into four sections: `extern crate`, `use`, `use crate`, and `use super`.
  - Example:
    ```rust
    extern crate serde;
    
    use std::collections::HashMap;
    use std::io::{self, Read};
    
    use crate::utils::config;
    
    use super::super::common::logger;
    ```
- **Braces**: Use the Allman style for braces, where the opening brace is on the same line as the function signature.
    - Example:
        ```rust
        fn main() {
            // function body
        }
        ```
- **Comments**: Use `//` for single-line comments and `/* ... */` for multi-line comments.
- **Whitespace**: Use a single space after commas and colons, and no space before commas and colons.
    - Example:
        ```rust
        let numbers = vec![1, 2, 3];
        let user = User { name: "Alice", age: 30 };
        ```
- **Function Length**: Aim to keep functions short and focused. If a function is too long, consider breaking it up into smaller functions.
- **Code Duplication**: Avoid duplicating code. If you find yourself copying and pasting code, consider refactoring it into a shared function or module.

## 2. Naming Conventions

- **Variables and Functions**: Use `snake_case`.
    - Example: `let user_name = "Alice";`
- **Structs and Enums**: Use `PascalCase`.
    - Example: `struct UserAccount { ... }`
- **Constants**: Use `UPPER_SNAKE_CASE`.
    - Example: `const MAX_USERS: u32 = 100;`
- **Module Names**: Use `snake_case`.
    - Example: `mod user_account;`

## 3. Documentation

- **Public Items**: All public functions, structs, and modules must have documentation comments using `///`.
  - Example:
    ```rust
    /// Creates a new user account.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the user.
    ///
    /// # Returns
    ///
    /// A `UserAccount` struct.
    pub fn create_user_account(name: &str) -> UserAccount {
        // function body
    }
    ```
- **Private Items**: Document private items where the intent or functionality is not immediately clear.
- **Module Documentation**: Each module should have a comment at the top explaining its purpose.
  - Example:
    ```rust
    //! This module contains utility functions for user management.
    
    // module contents
    ```

## 4. Error Handling

- **Use of `Result` and `Option`**:
  - Use `Result` for operations that can fail and `Option` for values that may or may not be present.
  - Example:
    ```rust
    fn find_user(id: u32) -> Option<User> {
        // function body
    }
    
    fn open_file(path: &str) -> Result<File, io::Error> {
        // function body
    }
    ```
- **Custom Error Types**: When appropriate, define custom error types using `enum` and implement the `anyhow::Error` trait.
- **Error Propagation**: Propagate errors using `?` where possible to simplify error handling.

