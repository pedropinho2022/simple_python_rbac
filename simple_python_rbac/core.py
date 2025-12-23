from functools import wraps
from typing import List, Dict, Optional, Callable, Any, Set
import glob
import yaml
from .exceptions import PermissionError

try:
    import streamlit as st
except ImportError:
    st = None

class RoleConfig:
    def __init__(self, role_name: str, description: Optional[str] = None, permissions: List[str] = None, permission_sets: List[str] = None):
        self.role_name = role_name
        self.description = description
        self.permissions = permissions or []
        self.permission_sets = permission_sets or []

class RBACManager:
    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True
        self.roles_db: Dict[str, RoleConfig] = {}
        self.permission_sets_db: Dict[str, List[str]] = {}
        self._current_role_provider: Optional[Callable[[], Optional[str]]] = None
        self.default_on_fail: Optional[Callable[[str], Any]] = None

    def set_roles(self, roles: List[Dict[str, Any]]):
        """
        Set roles from a list of dictionaries.
        Each dict should have 'role_name', 'permissions' and optionally 'permission_sets'.
        """
        self.roles_db.clear()
        for role_data in roles:
            role_name = role_data.get('role_name')
            if role_name:
                self.roles_db[role_name] = RoleConfig(
                    role_name=role_name,
                    description=role_data.get('description'),
                    permissions=role_data.get('permissions'),
                    permission_sets=role_data.get('permission_sets')
                )

    def set_permission_sets(self, permission_sets: Dict[str, List[str]]):
        """
        Sets the permission sets database.
        """
        self.permission_sets_db = permission_sets

    def load_roles_from_yaml(self, folder_path: str = "roles/*.yaml"):
        """
        Loads and validates all YAML files from a specified folder.
        """
        files = glob.glob(folder_path)
        if not files:
            print(f"RBAC Warning: No YAML files found in {folder_path}")

        for file in files:
            with open(file, 'r', encoding='utf-8') as f:
                try:
                    data = yaml.safe_load(f)
                    # Create RoleConfig from dictionary data
                    role = RoleConfig(**data)
                    self.roles_db[role.role_name] = role
                except Exception as e:
                    msg = f"RBAC Error: Failed to load role from {file}: {e}"
                    if st:
                        st.error(msg)
                    else:
                        print(msg)

    def load_permission_sets_from_yaml(self, file_path: str = "permission_sets.yaml"):
        """
        Loads permission sets from a YAML file.
        Expects a dictionary where keys are set names and values are lists of permissions.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    self.set_permission_sets(data)
        except Exception as e:
            msg = f"RBAC Error: Failed to load permission sets from {file_path}: {e}"
            if st:
                st.error(msg)
            else:
                print(msg)

    def validate_roles(self, defined_permissions: Set[str]) -> List[str]:
        """
        Safety Check:
        Verifies if permissions defined in roles and permission sets actually exist in your code constants.
        Returns a list of warning messages.
        """
        warnings = []

        # Validate permission sets
        for ps_name, ps_perms in self.permission_sets_db.items():
            for perm in ps_perms:
                self._check_permission_validity(perm, f"PermissionSet '{ps_name}'", defined_permissions, warnings)

        # Validate roles
        for role_name, role_config in self.roles_db.items():
            # Validate direct permissions
            for perm in role_config.permissions:
                self._check_permission_validity(perm, f"Role '{role_name}'", defined_permissions, warnings)

            # Validate permission set references
            for ps_name in role_config.permission_sets:
                if ps_name not in self.permission_sets_db:
                    warnings.append(f"Role '{role_name}': PermissionSet '{ps_name}' is not defined.")

        return warnings

    def _check_permission_validity(self, perm: str, context: str, defined_permissions: Set[str], warnings: List[str]):
        """Helper to validate a single permission string."""
        if perm == "*":
            return

        # Check hierarchical wildcards
        if perm.endswith(".*"):
            prefix = perm[:-2]
            # Check if any defined permission starts with this prefix
            has_match = any(p.startswith(prefix) for p in defined_permissions)
            if not has_match:
                warnings.append(f"{context}: Prefix '{perm}' does not match any code structure.")
            return

        # Exact check
        if perm not in defined_permissions:
            warnings.append(f"{context}: Permission '{perm}' is not defined in your constants.")

    def set_current_role_provider(self, provider: Callable[[], Optional[str]]):
        """
        Sets a function that returns the current user's role name.
        """
        self._current_role_provider = provider

    def _match_permission(self, user_perms: List[str], required_perm: str) -> bool:
        """
        Hierarchical matching logic:
        - Exact match: 'app.home.get' == 'app.home.get'
        - Wildcard match: 'app.*' allows 'app.home.get'
        """
        if "*" in user_perms:
            return True

        for perm in user_perms:
            if perm == required_perm:
                return True
            if perm.endswith("*"):
                prefix = perm[:-1]
                if required_perm.startswith(prefix):
                    return True
        return False

    def has_permission(self, required_perm: str, role_name: Optional[str] = None) -> bool:
        """
        Checks if the given role (or current role from provider) has the required permission.
        """
        if role_name is None:
            if self._current_role_provider:
                role_name = self._current_role_provider()
            else:
                return False

        if not role_name or role_name not in self.roles_db:
            return False

        role_config = self.roles_db[role_name]
        user_perms = list(role_config.permissions)

        # Add permissions from permission sets
        for ps_name in role_config.permission_sets:
            if ps_name in self.permission_sets_db:
                user_perms.extend(self.permission_sets_db[ps_name])

        return self._match_permission(user_perms, required_perm)

    def get_object_restrictions(self, role_name: str, object_type: str) -> Any:
        """
        Overload this method to return specific restrictions (e.g., filters) 
        for a given object type based on the role.
        """
        return None

    def require(self, permission: str, on_fail: Optional[Callable[[str], Any]] = None):
        """
        Generic decorator to require a permission.
        If on_fail is provided, it's called with the permission name when access is denied.
        If not provided, it uses the default_on_fail if set.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.has_permission(permission):
                    return func(*args, **kwargs)

                fail_handler = on_fail or self.default_on_fail
                if fail_handler:
                    return fail_handler(permission)

                raise PermissionError(f"Permission '{permission}' required.")
            return wrapper
        return decorator
