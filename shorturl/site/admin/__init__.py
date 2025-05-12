import logging
import os
import traceback

from dotenv import load_dotenv
from flask import (Blueprint, current_app, flash, g, make_response, redirect,
                   render_template, request, send_from_directory, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from ...database.db import ShortUrl, User, UserType
from ...database.exceptions import ElementDoesNotExsist
from ..access import admin_only
from ..forms import AdminEditUserForm, AdminNewUserForm

# from .views import admin_site, catalog_site

admin_site = Blueprint(
    "admin", __name__, template_folder="templates", url_prefix="/admin")


@admin_site.before_request
@login_required
@admin_only
def before_request():
    pass


@admin_site.route("/", methods=["GET", "POST"])
def admin():
    users = [u.to_dict() for u in User.get_all_users()]

    return render_template("admin/admin.html", users=users)


@admin_site.route("/new", methods=["GET", "POST"])
def new():
    form = AdminNewUserForm()

    if form.validate_on_submit():
        try:
            ut = UserType.get_via_id(form.type.data)
            User.create_new(form.username.data, form.password.data, ut)
        except Exception as e:
            form.username.errors.append(str(e))
        else:
            flash("User erstellt", "success")
            return redirect(url_for(".admin"))

    return render_template("admin/new.html", form=form)


@admin_site.route("/edit/<id>", methods=["GET", "POST"])
def edit(id: str):

    usr = User.get_via_id(id)

    form = AdminEditUserForm()

    if form.validate_on_submit():
        if form.delete.data:
            usr.delete()
            return redirect(url_for(".admin"))
        usr.set_password(form.password.data)
        flash(f"Passwort von {usr.username} aktualisiert", "success")
        return redirect(url_for(".admin"))

    form.password.data = usr.password_hash[:20] + "..."

    return render_template("admin/edit.html", form=form, user=usr.to_dict())
