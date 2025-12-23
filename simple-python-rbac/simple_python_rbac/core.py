from functools import wraps
from typing import List, Dict, Optional, Callable, Any

class RoleConfig:
    def __init__(self, role_name: str, description: Optional[str] = None, permissions: List[str] = None):
        self.role_name = role_name
        self.description = description
        self.permissions = permissions or []

class RBACManager:
    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True
        self.roles_db: Dict[str, RoleConfig] = {}
        self._current_role_provider: Optional[Callable[[], Optional[str]]] = None

    def set_roles(self, roles: List[Dict[str, Any]]):
        """
        Set roles from a list of dictionaries.
        Each dict should have 'role_name' and 'permissions'.
        """
        self.roles_db.clear()
        for role_data in roles:
            role_name = role_data.get('role_name')
            if role_name:
                self.roles_db[role_name] = RoleConfig(
                    role_name=role_name,
                    description=role_data.get('description'),
                    permissions=role_data.get('permissions')
                )

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

        user_perms = self.roles_db[role_name].permissions
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
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.has_permission(permission):
                    return func(*args, **kwargs)
                if on_fail:
                    return on_fail(permission)
                raise PermissionError(f"Permission '{permission}' required.")
            return wrapper
        return decorator
