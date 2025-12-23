class Permissions:
    """
    Base class for defining permissions in a hierarchical way.
    """
    pass

def get_all_permissions(cls):
    """Recursively scans a class and returns a set of all permission strings."""
    perms = set()

    def _scan(obj):
        # We use __dict__ instead of vars() for better compatibility if needed, 
        # but vars() is fine too.
        for name, value in vars(obj).items():
            if name.startswith("_"):
                continue

            if isinstance(value, str):
                perms.add(value)
            elif isinstance(value, type):
                _scan(value)

    _scan(cls)
    return perms
