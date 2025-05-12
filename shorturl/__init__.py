import logging
import os

from flask import Flask
from flask_login import LoginManager

from .database.db import User
from .database.seed import seed_database


def create_app():
    logging.basicConfig(level=logging.INFO)
    logging.info("Creating App")

    app = Flask(__name__)

    # Load configuration from environment variables
    app.config["BASE_URL"] = os.environ.get(
        "BASE_URL", "NO_BASE_URL_PROVIDED")

    # Security
    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", "default_secret_key")

    # Database
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///../instance/app.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.environ.get(
        "SQLALCHEMY_TRACK_MODIFICATIONS", "False"
    ).lower() in ["true", "1"]

    # Debugging
    app.config["DEBUG"] = os.environ.get(
        "FLASK_DEBUG", "False").lower() in ["true", "1"]
    app.config["WERKZEUGLOG"] = os.environ.get(
        "WERKZEUGLOG", "False").lower() in ["true", "1"]

    print("\n\n\n")
    print(f"SQLALCHEMY_DATABASE_URI: \
        {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"SQLALCHEMY_TRACK_MODIFICATIONS: \
        {app.config['SQLALCHEMY_TRACK_MODIFICATIONS']}")
    print("\n\n\n")

    logging.info(f"App Configuration: {app.config}")

    # Set Werkzeug logging level
    if not (app.config["WERKZEUGLOG"] or app.config["DEBUG"]):
        logging.getLogger("werkzeug").setLevel(logging.WARNING)

    # Initialize database
    from .database import db
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'site.login'
    login_manager.login_message_category = 'danger'

    @login_manager.user_loader
    def user_loader(user_id):
        return db.session.query(User).get(user_id)

    with app.app_context():
        db.create_all()

        # Seed database if it's empty
        NEW_DB = all(db.session.query(table).first()
                     is None for table in db.metadata.sorted_tables)

        if NEW_DB:
            app.logger.info("All tables are empty. Seeding database...")
            seed_database()

    # Register Blueprints
    from .site import site
    app.register_blueprint(site)

    print("Returning app")
    logging.info("App created successfully")
    return app
