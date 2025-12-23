import unittest
from simple_python_rbac import RBACManager, Permissions, PermissionError

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

if __name__ == "__main__":
    unittest.main()
