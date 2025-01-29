from functools import wraps

from flask import abort
from flask_login import current_user

from ..database.db import User


def admin_only(f):
    return _check_permission(1)(f)


def editor_only(f):
    return _check_permission(2)(f)


def viewer_only(f):
    return _check_permission(3)(f)


def _check_permission(value):
    """
    Decorator to check if the user has the permission to access the route
    :param value: the permission level
    :return: the decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            usr: User = current_user
            if (not usr.is_authenticated) or (not value >= usr.user_type_id):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
