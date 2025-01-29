import logging
import os
import traceback

from dotenv import load_dotenv
from flask import (Blueprint, current_app, flash, g, make_response, redirect,
                   render_template, request, send_from_directory, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from ..database.db import ShortUrl, User, UserType
from ..database.exceptions import ElementDoesNotExsist
from .admin import admin_site
from .forms import ChangePasswordForm, LoginForm
from .manage import manage_site

load_dotenv()

site = Blueprint("site", __name__, template_folder="templates")

site.register_blueprint(manage_site)
site.register_blueprint(admin_site)


@site.app_errorhandler(403)
def error403(err):
    context = dict(inject_views())
    context.update({"msg": str(err)})
    return make_response(render_template("errors/403.html", **context), 403)


@site.app_errorhandler(404)
def error404(err):
    context = dict(inject_views())
    context.update({"msg": str(err)})
    return make_response(render_template("errors/404.html", **context), 404)


@site.app_errorhandler(405)
def error405(err):
    context = dict(inject_views())
    context.update({"msg": str(err)})
    return make_response(render_template("errors/405.html", **context), 405)


@site.app_errorhandler(400)
@site.app_errorhandler(500)
def error500(err):
    tb = traceback.format_exc()
    logging.critical(str(err).replace("\n", "\\n") +
                     "\\n" + str(tb).replace("\n", "\\n"))
    context = dict(inject_views())
    context.update({"msg": str(err)})
    context.update({"traceback": tb})
    return make_response(render_template("errors/500.html", **context), 500)


@site.errorhandler(ElementDoesNotExsist)
def handle_element_does_not_exist(error):
    return error404(error)


@site.errorhandler(Exception)
def handle_exception(error):
    return error500(error)


@site.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


@site.context_processor
def inject_views():
    data = {}
    usr: User = current_user

    data["cuser"] = {"is_authenticated": usr.is_authenticated}

    if usr.is_authenticated:
        data["cuser"].update({"name": usr.username,
                              "role": UserType.get_via_id(usr.user_type_id).name
                              })

    views = []
    views.append({"name": "Startseite",
                  "url": url_for("site.index")})
    # views.append({"name": "Katalog",
    #               "url": url_for("site.catalog.catalog")})
    if usr.is_authenticated:
        if usr.user_type_id == UserType.get_id_by_name("admin"):
            views.append({"name": "Admin",
                          "url": "/"})
            # "url": url_for("site.admin.index")})
    data["views"] = views

    return data


@site.before_request
def check_user_active():
    usr: User = current_user
    if usr.is_authenticated:
        if not usr.active:
            logout_user()
            return redirect(url_for("site.login"))


@site.route("/")
def index():
    return render_template("index.html")


@site.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(current_app.root_path, 'static'),
                               'favicon.png')


@site.route("/login", methods=["GET", "POST"])
def login():
    form: LoginForm = LoginForm()
    form.errors.clear()
    if request.method == "POST":
        if form.validate_on_submit():
            username = form.username.data.strip()
            password = form.password.data.strip()
            usr = User.get_via_id(username)

            if usr is not None and usr.check_password(password):
                if not usr.active:
                    flash("Nutzerkonto ist deaktiviert", "danger")
                    return render_template("login.html", form=form)
                else:
                    login_user(usr, remember=True)
                    logging.info(
                        f"Login from: {request.remote_addr} successful as {usr.username}")
                    return redirect(request.args.get('next') or url_for("site.manage.manage"))
            logging.info(
                f"Login attempt from: {request.remote_addr} with username: {username} failed")
            form.password.errors.append("Nutzername oder Passwort Falsch")
            return render_template("login.html", form=form)

        current_app.logger.warning(f"Form not validated: {form.errors}")

    if current_user.is_authenticated:
        return redirect(url_for("site.manage.manage"))

    return render_template("login.html", form=form)


@site.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for(".index"))


@site.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


@site.route("/changePassword", methods=["GET", "POST"])
@login_required
def change_password():
    usr: User = current_user
    form: ChangePasswordForm = ChangePasswordForm()

    if form.validate_on_submit():
        # Dummy logic for changing the password
        usr.set_password(form.new_password.data)
        flash('Passwort erfolgreich geändert', 'success')
        logout_user()
        return redirect(url_for('.index'))

    return render_template("changePassword.html", form=form)


@site.route("/<path:id>", methods=["GET", "POST"])
def short(id):
    try:
        ShortUrl.get_via_id(id)
    except ElementDoesNotExsist:
        return render_template("nonexistent.html"), 404
    return redirect(ShortUrl.get_via_id(id).endpoint)


@site.route("/t/<path:id>", methods=["GET", "POST"])
def short_test(id):
    return id
