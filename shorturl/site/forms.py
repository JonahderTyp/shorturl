import re

from flask_wtf import FlaskForm
from wtforms.fields import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import (URL, DataRequired, EqualTo, Length, Optional,
                                ValidationError)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

    # def validate_password(self, password):
    #     if password.data != 'correctpassword':
    #         raise ValidationError('Falsches Passwort oder Benutzername')


class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password',
                                     validators=[
                                         DataRequired(),
                                         EqualTo(
                                             'new_password', message='Passwords must match.')
                                     ])
    submit = SubmitField('Passwort Ändern')


class AdminChangePasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    passsubmit = SubmitField('Change Password')


class AdminChangeTypeForm(FlaskForm):
    type = SelectField('Type', choices=[
                       ('1', 'Admin'), ('2', 'Editor'), ('3', 'Viewer')], validators=[DataRequired()])
    typesubmit = SubmitField('Change Type')


class AdminChangeActiveForm(FlaskForm):
    active = SelectField('Active', choices=[
        ('1', 'Active'), ('0', 'Inactive')], validators=[DataRequired()])
    actsubmit = SubmitField('Change Active')


class AdminNewUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    type = SelectField('Type', choices=[
                       ('1', 'Admin'), ('2', 'Editor'), ('3', 'Viewer')], validators=[DataRequired()])
    submit = SubmitField('Create User')


def validate_and_fix_url(form, field):
    url = field.data.strip()

    # Regex to match a full URL (with http:// or https://)
    full_url_regex = re.compile(
        r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    )

    # Regex to match a domain-only format (without http:// or https://)
    domain_regex = re.compile(
        r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s]*)?$'
    )

    if url.startswith(("http://", "https://")):
        # Ensure it's a valid full URL
        if not full_url_regex.match(url):
            raise ValidationError(
                "Invalid URL format. Ensure it's correctly formatted.")
    else:
        # Ensure it's a valid domain (allowing missing scheme)
        if not domain_regex.match(url):
            raise ValidationError(
                "Invalid URL format. Provide a valid domain or full URL.")

        # Auto-prepend "https://" since it's missing
        field.data = f"https://{url}"


def strip_whitespace(form, field):
    """Custom validator to strip leading/trailing whitespace from input."""
    field.data = field.data.strip()


class NewShortUrlForm(FlaskForm):
    short = StringField('Short', validators=[DataRequired(), strip_whitespace])
    description = StringField('Description', validators=[Optional()])
    endpoint = StringField('Endpoint', validators=[
                           DataRequired(), validate_and_fix_url])
    submit = SubmitField('Create ShortUrl')


class EditShortUrlForm(FlaskForm):
    description = StringField('Description', validators=[Optional()])
    endpoint = StringField('Endpoint', validators=[
                           DataRequired(), validate_and_fix_url])
    delete = SubmitField("Delete Task", name="delete")
    submit = SubmitField('Save Changes')


class NewUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Create User')


class EditUserForm(FlaskForm):
    password = StringField('Password', validators=[DataRequired()])
    delete = SubmitField("Delete Task", name="delete")
    submit = SubmitField('Save Changes')
