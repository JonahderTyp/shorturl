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
from ..forms import (ChangePasswordForm, EditShortUrlForm, LoginForm,
                     NewShortUrlForm)

# from .views import admin_site, catalog_site

manage_site = Blueprint(
    "manage", __name__, template_folder="templates", url_prefix="/manage")


@manage_site.before_request
@login_required
def before_request():
    pass


@manage_site.route("/", methods=["GET", "POST"])
def manage():
    usr: User = current_user

    shorturls = [u.to_dict() for u in usr.urls]

    print(shorturls)
    return render_template("manage/manage.html", shorturls=shorturls)


@manage_site.route("/new", methods=["GET", "POST"])
def new():
    usr: User = current_user

    form = NewShortUrlForm()

    if form.validate_on_submit():
        try:
            shorturl = ShortUrl.create_new(
                form.short.data, form.description.data, form.endpoint.data, usr)

        except Exception as e:
            form.short.errors.append(str(e))
        else:
            flash("ShortUrl erstellt", "success")
            return redirect(url_for(".manage"))

    return render_template("manage/new.html", form=form)


@manage_site.route("/edit/<id>", methods=["GET", "POST"])
def edit(id: str):
    usr: User = current_user
    shorturl = ShortUrl.get_via_id(id)
    if not shorturl or shorturl.user != usr:
        flash("ShortUrl existiert nicht oder gehört nicht dir", "danger")
        return redirect(url_for(".manage"))

    form = EditShortUrlForm()

    if form.validate_on_submit():
        if form.delete.data:
            shorturl.delete()
            return redirect(url_for(".index"))
        shorturl.endpoint = form.endpoint.data
        shorturl.description = form.description.data
        shorturl.save()
        flash("ShortUrl aktualisiert", "success")
        return redirect(url_for(".manage"))

    form.description.data = shorturl.description
    form.endpoint.data = shorturl.endpoint

    return render_template("manage/edit.html", shorturl=shorturl, form=form)
