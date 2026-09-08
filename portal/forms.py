#!/usr/bin/env python3
"""
forms.py

WTForms definitions for every input in the portal.

Two things happen here that matter for security. Flask-WTF adds a CSRF token
to every form, and every field is validated against an explicit whitelist
pattern before it reaches the database layer. Combined with the ORM, which
only ever emits bound parameters, there is no path where user input becomes
part of an SQL statement.
"""

import re

from flask_wtf import FlaskForm
from wtforms import (BooleanField, IntegerField, PasswordField, SelectField, StringField,
                     TextAreaField)
from wtforms.validators import (DataRequired, Email, EqualTo, Length, NumberRange, Optional,
                                Regexp, ValidationError)

from portal.models import (API_SCOPE_READ, API_SCOPE_WRITE, AUTH_CERT,
                           AUTH_SECRET, ROLES, ROLE_LABELS)

GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
KEY_PATTERN = r"^[a-z0-9][a-z0-9-]{1,47}$"
USERNAME_PATTERN = r"^[a-zA-Z0-9._-]{3,64}$"


class GuidField(StringField):
    """String field that only accepts a canonical GUID."""

    def pre_validate(self, form):
        """Reject anything that is not a GUID before the form is used."""
        if self.data and not GUID.match(self.data.strip()):
            raise ValidationError("Muss eine GUID sein, z.B. "
                                  "00000000-0000-0000-0000-000000000000")


def schluessel_hinweis(wert):
    """
    Return the specific reason why a customer key is invalid, or None.

    Uppercase is the mistake that happens in practice: the display name of the
    customer gets typed into the key field, and the generic pattern message
    leaves the reader guessing which of the four rules was broken. Naming the
    lowercase form outright turns the error into an instruction.

    Ein leerer Wert ist ungueltig und bekommt deshalb eine Meldung. Die
    Funktion darf nicht "leer heisst in Ordnung" antworten: das Formular faengt
    den Fall zwar zusaetzlich mit DataRequired ab, die Schnittstelle hat kein
    solches Gegenstueck, und ein leerer Schluessel erzeugt dort einen Kunden,
    den danach keine Route mehr adressieren kann.
    """
    if not wert:
        return ("Pflichtfeld. Kleinbuchstaben, Ziffern und Bindestrich, "
                "2 bis 48 Zeichen, z.B. contoso")
    if wert != wert.lower():
        klein = wert.lower()
        if re.match(KEY_PATTERN, klein):
            return ("Grossbuchstaben sind im Schlüssel nicht erlaubt. "
                    "Verwende %s." % klein)
        return ("Grossbuchstaben sind im Schlüssel nicht erlaubt. Verwende "
                "ausschliesslich Kleinbuchstaben, Ziffern und Bindestrich.")
    if not re.match(KEY_PATTERN, wert):
        return ("Kleinbuchstaben, Ziffern und Bindestrich, 2 bis 48 Zeichen, "
                "Beginn mit Buchstabe oder Ziffer, z.B. contoso")
    return None


class KeyField(StringField):
    """Customer key field that says what is wrong, not just that something is."""

    def pre_validate(self, form):
        """Reject an invalid key with the reason that applies to this value."""
        meldung = schluessel_hinweis((self.data or "").strip())
        if meldung:
            raise ValidationError(meldung)


class LoginForm(FlaskForm):
    """Step one of the login: account and password."""

    username = StringField("Benutzername", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Passwort", validators=[DataRequired(), Length(max=128)])


class TotpForm(FlaskForm):
    """Step two of the login: the six digit code or a recovery code."""

    code = StringField("Code", validators=[DataRequired(), Length(min=6, max=16)])


class PasswordForm(FlaskForm):
    """Password change for the signed in account."""

    current_password = PasswordField("Aktuelles Passwort",
                                     validators=[DataRequired(), Length(max=128)])
    new_password = PasswordField("Neues Passwort", validators=[DataRequired(), Length(max=128)])
    confirm_password = PasswordField(
        "Neues Passwort wiederholen",
        validators=[DataRequired(), EqualTo("new_password", "Die Passwörter stimmen nicht überein")])


class StepUpForm(FlaskForm):
    """Password plus current code, required before replacing the second factor."""

    current_password = PasswordField("Aktuelles Passwort",
                                     validators=[DataRequired(), Length(max=128)])
    code = StringField("Aktueller Code", validators=[DataRequired(), Length(min=6, max=16)])


class UserForm(FlaskForm):
    """Create or edit a portal account."""

    username = StringField("Benutzername", validators=[
        DataRequired(), Regexp(USERNAME_PATTERN,
                               message="Erlaubt sind Buchstaben, Ziffern, Punkt, Bindestrich "
                                       "und Unterstrich, 3 bis 64 Zeichen")])
    display_name = StringField("Anzeigename", validators=[Optional(), Length(max=128)])
    email = StringField("E-Mail", validators=[Optional(), Email(), Length(max=190)])
    role = SelectField("Rolle", choices=[(r, ROLE_LABELS[r]) for r in ROLES],
                       validators=[DataRequired()])
    is_active = BooleanField("Aktiv", default=True)
    password = PasswordField("Passwort", validators=[Optional(), Length(max=128)])


class CustomerForm(FlaskForm):
    """Create or edit one monitored customer tenant."""

    key = KeyField("Schlüssel", validators=[DataRequired()])
    display_name = StringField("Anzeigename", validators=[DataRequired(), Length(max=128)])
    tenant_id = GuidField("Tenant-ID (Verzeichnis-ID)", validators=[DataRequired()])
    client_id = GuidField("Client-ID (Anwendungs-ID)", validators=[DataRequired()])

    # Client Secret steht zuerst und ist die Vorgabe: es funktioniert in jedem
    # Tenant und auf jeder Instanz, ohne Zertifikatsspeicher und ohne Rechte
    # auf einen privaten Schluessel. Das Zertifikat bleibt fuer Tenants, die
    # Client Secrets per Richtlinie verbieten oder begrenzen.
    auth_type = SelectField("Authentisierung", choices=[
        (AUTH_SECRET, "Client Secret (empfohlen)"),
        (AUTH_CERT, "Zertifikat")], validators=[DataRequired()],
        default=AUTH_SECRET)
    client_secret = PasswordField("Client Secret", validators=[Optional(), Length(max=512)])
    cert_pem = TextAreaField("Zertifikat (PEM)", validators=[Optional(), Length(max=20000)])
    key_pem = TextAreaField("Privater Schlüssel (PEM)",
                            validators=[Optional(), Length(max=20000)])

    warn_days = IntegerField("Warnung ab Restlaufzeit (Tage)",
                             validators=[DataRequired(), NumberRange(min=1, max=3650)], default=30)
    error_days = IntegerField("Fehler ab Restlaufzeit (Tage)",
                              validators=[DataRequired(), NumberRange(min=1, max=3650)], default=14)
    max_channels = IntegerField("Maximale PRTG-Kanäle",
                                validators=[DataRequired(), NumberRange(min=1, max=200)],
                                default=45)
    include_sp = BooleanField("Enterprise Apps mitprüfen")
    show_expired = BooleanField("Abgelaufene Credentials anzeigen")
    app_filter = StringField("Nur Anwendungen mit diesem Namensteil",
                            validators=[Optional(), Length(max=190)])
    app_exclude = StringField("Anwendungen ausschliessen (kommagetrennt)",
                             validators=[Optional(), Length(max=190)])
    notes = TextAreaField("Notizen", validators=[Optional(), Length(max=4000)])
    is_active = BooleanField("Aktiv überwachen", default=True)

    def validate(self, extra_validators=None):
        """Enforce that the chosen authentication method is actually filled in."""
        # Die Vorgabe auf dem Feld gilt nur fuer ein leeres Formular. Kommt eine
        # Absendung ohne auth_type herein, darf sie nicht stillschweigend auf
        # Secret fallen: bei einem Zertifikatskunden wuerde das die Anmeldeart
        # umstellen und cert_pem samt privatem Schluessel loeschen, ohne dass
        # jemand die Umstellung angefordert hat. DataRequired sieht den Fall
        # nicht, weil der Default das Feld bereits gefuellt hat.
        if self.is_submitted() and not self.auth_type.raw_data:
            self.auth_type.errors = list(self.auth_type.errors) + [
                "Anmeldeart fehlt. Client Secret oder Zertifikat wählen."]
            return False
        if not super().validate(extra_validators):
            return False
        if self.error_days.data and self.warn_days.data and \
                self.error_days.data > self.warn_days.data:
            self.error_days.errors.append("Fehlergrenze muss kleiner oder gleich der "
                                          "Warngrenze sein")
            return False
        return True


class ConfirmForm(FlaskForm):
    """Empty form used to CSRF protect buttons such as force check or delete."""


class ApiKeyForm(FlaskForm):
    """Name and scope of a new API key."""

    name = StringField("Bezeichnung", validators=[
        DataRequired(), Length(min=3, max=128),
        Regexp(r"^[A-Za-z0-9 ._-]+$",
               message="Buchstaben, Ziffern, Leerzeichen, Punkt, Unterstrich, Bindestrich")])
    scope = SelectField("Bereich", choices=[(API_SCOPE_READ, "Nur Lesen"),
                                            (API_SCOPE_WRITE, "Lesen und Schreiben")],
                        default=API_SCOPE_READ, validators=[DataRequired()])
