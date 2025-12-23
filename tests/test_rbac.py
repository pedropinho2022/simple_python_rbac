import unittest
import os
import tempfile
import yaml
from unittest.mock import MagicMock, patch
from simple_python_rbac import RBACManager, Permissions, PermissionError, get_all_permissions

class MyPermissions(Permissions):
    class App:
        _prefix = "app"
        GET = f"{_prefix}.get"
        LIST = f"{_prefix}.list"
    
    class Admin:
        _prefix = "admin"
        ALL = f"{_prefix}.*"

class TestRBAC(unittest.TestCase):
    def setUp(self):
        # RBACManager is a singleton, so we need to reset it for tests
        self.rbac = RBACManager()
        self.rbac.roles_db.clear()
        self.rbac._current_role_provider = None
        
        roles = [
            {
                "role_name": "viewer",
                "permissions": [MyPermissions.App.GET]
            },
            {
                "role_name": "editor",
                "permissions": ["app.*"]
            },
            {
                "role_name": "admin",
                "permissions": ["*"]
            }
        ]
        self.rbac.set_roles(roles)

    def test_exact_match(self):
        self.assertTrue(self.rbac.has_permission(MyPermissions.App.GET, "viewer"))
        self.assertFalse(self.rbac.has_permission(MyPermissions.App.LIST, "viewer"))

    def test_wildcard_match(self):
        self.assertTrue(self.rbac.has_permission(MyPermissions.App.GET, "editor"))
        self.assertTrue(self.rbac.has_permission(MyPermissions.App.LIST, "editor"))
        self.assertFalse(self.rbac.has_permission("admin.all", "editor"))

    def test_superuser_match(self):
        self.assertTrue(self.rbac.has_permission(MyPermissions.App.GET, "admin"))
        self.assertTrue(self.rbac.has_permission("any.random.permission", "admin"))

    def test_current_role_provider(self):
        self.rbac.set_current_role_provider(lambda: "viewer")
        self.assertTrue(self.rbac.has_permission(MyPermissions.App.GET))
        self.assertFalse(self.rbac.has_permission(MyPermissions.App.LIST))

    def test_decorator_pass(self):
        self.rbac.set_current_role_provider(lambda: "editor")
        
        @self.rbac.require(MyPermissions.App.LIST)
        def secret_function():
            return "success"
        
        self.assertEqual(secret_function(), "success")

    def test_decorator_fail(self):
        self.rbac.set_current_role_provider(lambda: "viewer")
        
        @self.rbac.require(MyPermissions.App.LIST)
        def secret_function():
            return "success"
        
        with self.assertRaises(PermissionError):
            secret_function()

    def test_decorator_fail_custom_callback(self):
        self.rbac.set_current_role_provider(lambda: "viewer")
        
        def on_fail(perm):
            return f"Access denied to {perm}"
            
        @self.rbac.require(MyPermissions.App.LIST, on_fail=on_fail)
        def secret_function():
            return "success"
        
        self.assertEqual(secret_function(), "Access denied to app.list")

    def test_object_restrictions_overload(self):
        class RestrictedRBAC(RBACManager):
            def get_object_restrictions(self, role_name, object_type):
                if role_name == "viewer" and object_type == "data":
                    return {"filter": "status='public'"}
                return None
        
        # Note: Since RBACManager is a singleton, this might be tricky if already instantiated.
        # But for the sake of the example/test:
        rbac_restricted = RestrictedRBAC()
        restrictions = rbac_restricted.get_object_restrictions("viewer", "data")
        self.assertEqual(restrictions, {"filter": "status='public'"})

    def test_default_on_fail(self):
        self.rbac.set_current_role_provider(lambda: "viewer")
        
        def global_fail(perm):
            return f"Global fail: {perm}"
        
        self.rbac.default_on_fail = global_fail
        
        @self.rbac.require("some.perm")
        def protected_func():
            return "ok"
            
        self.assertEqual(protected_func(), "Global fail: some.perm")

    def test_permission_sets(self):
        # Setup permission sets
        permission_sets = {
            "view_all": ["app.get", "app.list"],
            "edit_all": ["app.create", "app.update", "app.delete"]
        }
        self.rbac.set_permission_sets(permission_sets)
        
        # Setup role with permission sets
        roles = [
            {
                "role_name": "manager",
                "permissions": ["audit.log"],
                "permission_sets": ["view_all", "edit_all"]
            }
        ]
        self.rbac.set_roles(roles)
        
        self.assertTrue(self.rbac.has_permission("audit.log", "manager"))
        self.assertTrue(self.rbac.has_permission("app.get", "manager"))
        self.assertTrue(self.rbac.has_permission("app.update", "manager"))

class TestRBACExpansion(unittest.TestCase):
    def setUp(self):
        self.manager = RBACManager()
        self.manager.roles_db.clear()
        self.manager.permission_sets_db.clear()
        self.manager.default_on_fail = None

    def test_singleton_init_guard(self):
        # Trigger the guard
        self.manager.__init__()
        self.assertTrue(self.manager._initialized)

    def test_get_all_permissions_nested(self):
        class NestedPerms(Permissions):
            READ = "read"
            class User:
                CREATE = "user.create"
            class _Internal:
                SECRET = "secret"
        
        perms = get_all_permissions(NestedPerms)
        self.assertIn("read", perms)
        self.assertIn("user.create", perms)
        self.assertNotIn("secret", perms)

    def test_load_roles_from_yaml_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            role_data = {
                "role_name": "admin_yaml",
                "permissions": ["*"]
            }
            file_path = os.path.join(tmpdir, "admin.yaml")
            with open(file_path, "w") as f:
                yaml.dump(role_data, f)
            
            self.manager.load_roles_from_yaml(os.path.join(tmpdir, "*.yaml"))
            self.assertIn("admin_yaml", self.manager.roles_db)

    def test_load_roles_from_yaml_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "corrupt.yaml")
            with open(file_path, "w") as f:
                f.write("invalid: yaml: :")
            self.manager.load_roles_from_yaml(os.path.join(tmpdir, "*.yaml"))
            self.assertNotIn("invalid", self.manager.roles_db)

    def test_load_permission_sets_from_yaml_success(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            ps_data = {"viewer_set": ["read"]}
            yaml.dump(ps_data, tmp)
            tmp_path = tmp.name
        try:
            self.manager.load_permission_sets_from_yaml(tmp_path)
            self.assertIn("viewer_set", self.manager.permission_sets_db)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_validate_roles_comprehensive(self):
        defined = {"app.read"}
        self.manager.set_permission_sets({"ps1": ["wrong.perm"]})
        self.manager.set_roles([
            {"role_name": "r1", "permissions": ["app.read", "missing.perm"], "permission_sets": ["ps1", "ps_missing"]}
        ])
        warnings = self.manager.validate_roles(defined)
        warning_str = "\n".join(warnings)
        self.assertIn("PermissionSet 'ps1': Permission 'wrong.perm' is not defined", warning_str)
        self.assertIn("Role 'r1': Permission 'missing.perm' is not defined", warning_str)
        self.assertIn("Role 'r1': PermissionSet 'ps_missing' is not defined", warning_str)

    def test_validate_roles_wildcards(self):
        defined = {"app.read"}
        self.manager.set_roles([
            {"role_name": "r1", "permissions": ["app.*", "none.*", "*"]}
        ])
        warnings = self.manager.validate_roles(defined)
        self.assertEqual(len(warnings), 1)
        self.assertIn("Prefix 'none.*' does not match any code structure", warnings[0])

    def test_has_permission_edge_cases(self):
        self.assertFalse(self.manager.has_permission("any"))
        self.manager.set_current_role_provider(lambda: None)
        self.assertFalse(self.manager.has_permission("any"))
        self.assertFalse(self.manager.has_permission("any", role_name="ghost"))

    def test_get_object_restrictions_base(self):
        self.assertIsNone(self.manager.get_object_restrictions("admin", "user"))

    def test_error_handling_streamlit_mock(self):
        import simple_python_rbac.core
        mock_st = MagicMock()
        old_st = simple_python_rbac.core.st
        simple_python_rbac.core.st = mock_st
        try:
            self.manager.load_permission_sets_from_yaml("non_existent.yaml")
            mock_st.error.assert_called()
        finally:
            simple_python_rbac.core.st = old_st

    def test_error_handling_no_streamlit_print(self):
        import simple_python_rbac.core
        old_st = simple_python_rbac.core.st
        simple_python_rbac.core.st = None
        try:
            with patch('builtins.print') as mock_print:
                self.manager.load_permission_sets_from_yaml("non_existent.yaml")
                mock_print.assert_called()
        finally:
            simple_python_rbac.core.st = old_st

if __name__ == "__main__":
    unittest.main()
