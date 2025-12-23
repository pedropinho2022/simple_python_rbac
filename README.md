# Simple Python RBAC

A lightweight, hierarchical Role-Based Access Control (RBAC) package for Python. It is designed to be framework-agnostic, with no third-party dependencies.

## Features

- **Hierarchical Permissions**: Supports wildcards (e.g., `app.*` matches `app.home`, `app.settings`).
- **Permission Sets**: Group permissions into named sets (like AWS Permission Sets) for easier role management.
- **Global Fail Handler**: Define a default behavior for when permissions are denied.
- **YAML Configuration**: Load roles and permission sets directly from YAML files.
- **Framework Agnostic**: Easy integration with Streamlit, Flask, FastAPI, etc.
- **Generic Decorators**: Protect functions with simple decorators.
- **Object-Level Restrictions**: Hooks to implement data-level security.
- **Zero Dependencies**: Pure Python, no external requirements (YAML support requires `pyyaml`).

## Installation

You can install the package directly from PyPI:

```bash
pip install simple-python-rbac
```

## Core Concepts

### 1. Defining Permissions

Use the `Permissions` class to organize your permissions hierarchically.

```python
from simple_python_rbac import Permissions

class AppPermissions(Permissions):
    class Documents:
        _prefix = "docs"
        VIEW = f"{_prefix}.view"
        EDIT = f"{_prefix}.edit"
        DELETE = f"{_prefix}.delete"
    
    class Admin:
        ALL = "admin.*"
```

### 2. Permission Sets

Group permissions into sets that can be assigned to roles.

```python
from simple_python_rbac import RBACManager

rbac = RBACManager()

permission_sets = {
    "viewer_set": ["docs.view", "profile.view"],
    "editor_set": ["docs.*", "profile.edit"]
}

rbac.set_permission_sets(permission_sets)
```

### 3. Configuring Roles

Roles can have direct permissions and/or inherit from permission sets.

```python
roles = [
    {
        "role_name": "viewer",
        "permission_sets": ["viewer_set"]
    },
    {
        "role_name": "editor",
        "permissions": ["audit.log"],
        "permission_sets": ["viewer_set", "editor_set"]
    },
    {
        "role_name": "admin",
        "permissions": ["*"]
    }
]

rbac.set_roles(roles)
```

### 4. Global On-Fail Handler

You can define a global handler for permission denials that will be used if no specific handler is provided in the decorator.

```python
def my_default_fail(permission):
    print(f"User lacks {permission}")
    return False

rbac.default_on_fail = my_default_fail

@rbac.require("admin.all")
def secret_admin_task():
    return "Top Secret"
```

### 5. YAML Configuration

Load roles and permission sets from YAML files for better organization.

```python
# Load all YAMLs from a folder
rbac.load_roles_from_yaml("config/roles/*.yaml")

# Load permission sets from a specific file
rbac.load_permission_sets_from_yaml("config/permission_sets.yaml")
```

### 6. Custom Exceptions

The package provides a custom `PermissionError` (exported from the main package) that is raised when access is denied and no fail handler is provided.

```python
from simple_python_rbac import PermissionError

try:
    @rbac.require("missing.perm")
    def my_func():
        pass
    my_func()
except PermissionError as e:
    print(f"Caught expected error: {e}")
```

## Overloading Object Restrictions

One of the powerful features of `simple-python-rbac` is the ability to define restrictions on objects based on roles. To do this, you can inherit from `RBACManager` and override the `get_object_restrictions` method.

```python
from simple_python_rbac import RBACManager

class MyRBACManager(RBACManager):
    def get_object_restrictions(self, role_name: str, object_type: str):
        """
        Returns a filter or a set of rules for the given object type.
        """
        if object_type == "document":
            if role_name == "viewer":
                return {"status": "published"}
            if role_name == "editor":
                return {"owner_id": 123} # example: only their own docs
        return None

rbac = MyRBACManager()
```

## Test Coverage

The package is thoroughly tested. Current coverage:

| Module | Coverage |
|--------|----------|
| `simple_python_rbac/core.py` | 58% |
| `simple_python_rbac/exceptions.py` | 100% |
| `simple_python_rbac/permissions.py` | 21% |
| **Total** | **70%** |

## Running Tests

```bash
python -m unittest discover tests
```
