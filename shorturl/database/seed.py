import random

from .db import ShortUrl, User, UserType


def seed_database():
    """ Seed database with admin user """
    admin = UserType.create_new("admin")
    user = UserType.create_new("user")

    User.create_new("admin", "admin", admin)
