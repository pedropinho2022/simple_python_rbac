# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-12-23

### Added
- Comprehensive test suite increasing coverage to 97%.
- `.gitignore` file to manage build artifacts and IDE configurations.
- Git tag `v0.3.0` for formal release marking.

### Changed
- Improved `validate_roles` logic for wildcard patterns.
- Optimized repository structure by removing unnecessary tracked files (`.idea`, `.pyc`, etc.).

## [0.2.0] - 2025-12-23

### Added
- Support for `default_on_fail` global handler in `RBACManager`.
- `PermissionSet` functionality to group permissions.
- `PermissionError` custom exception class.
- YAML support for loading roles and permission sets.
- Enhanced `README.md` with features, examples, and test coverage table.

### Changed
- Updated `require` decorator to support both global and local `on_fail` handlers.
- Refactored project structure to the root directory for better GitHub visibility.
- Improved error handling for Streamlit and YAML loading.

### Fixed
- Missing imports in `core.py` (`glob`, `yaml`, `Set`).
- Bug in `validate_roles` when checking permission set references.

## [0.1.0] - 2025-12-23

### Added
- Initial release with basic RBAC functionality.
- Hierarchical permission matching with wildcards.
- Role management and current role provider support.
- Function decorators for permission enforcement.
- Support for object-level restrictions hooks.
