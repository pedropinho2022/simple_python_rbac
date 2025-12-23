# Simple Python RBAC

A lightweight, hierarchical Role-Based Access Control (RBAC) package for Python. It is designed to be framework-agnostic, with no third-party dependencies.

## Features

- **Hierarchical Permissions**: Supports wildcards (e.g., `app.*` matches `app.home`, `app.settings`).
- **Framework Agnostic**: Easy integration with Streamlit, Flask, FastAPI, etc.
- **Generic Decorators**: Protect functions with simple decorators.
- **Object-Level Restrictions**: Hooks to implement data-level security.
- **Zero Dependencies**: Pure Python, no external requirements.

## Installation

You can install the package directly from the source directory:

```bash
pip install .
```

Or from PyPI (once published):

```bash
pip install simple-python-rbac
```

> **Note**: While the package uses the modern `pyproject.toml` configuration, a minimal `setup.py` is included for compatibility with older tools and to facilitate editable installs (`pip install -e .`).

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

### 2. Configuring Roles

Roles are defined by a name and a list of permissions.

```python
from simple_python_rbac import RBACManager

rbac = RBACManager()

roles = [
    {
        "role_name": "viewer",
        "permissions": ["docs.view"]
    },
    {
        "role_name": "editor",
        "permissions": ["docs.*"]
    },
    {
        "role_name": "admin",
        "permissions": ["*"]
    }
]

rbac.set_roles(roles)
```

### 3. Current Role Provider

You must tell the manager how to find the current user's role.

```python
# Example for a simple script
rbac.set_current_role_provider(lambda: "viewer")
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
# ... set roles and provider ...

# Use it in your code:
restrictions = rbac.get_object_restrictions("viewer", "document")
# Use 'restrictions' to filter your database query
```

## Framework Examples

### Streamlit Example

```python
import streamlit as st
from simple_python_rbac import RBACManager

rbac = RBACManager()
# Configure roles...
rbac.set_current_role_provider(lambda: st.session_state.get("user_role"))

def on_rbac_fail(permission):
    st.error(f"⛔ Access Denied: You need '{permission}' permission.")
    st.stop()

@rbac.require("docs.edit", on_fail=on_rbac_fail)
def edit_document():
    st.write("Editing document...")

if st.button("Edit"):
    edit_document()
```

### Flask Example

```python
from flask import Flask, abort, g
from simple_python_rbac import RBACManager

app = Flask(__name__)
rbac = RBACManager()

# Configure roles...
rbac.set_current_role_provider(lambda: getattr(g, "user_role", None))

def on_flask_fail(permission):
    abort(403)

@app.route("/edit")
@rbac.require("docs.edit", on_fail=on_flask_fail)
def edit():
    return "Editing document..."
```

## Running Tests

```bash
python -m unittest discover tests
```
