"""Schémas de validation - protection contre Mass Assignment"""
from marshmallow import Schema, fields, validate, ValidationError, RAISE


class RegisterSchema(Schema):
    """✅ Allowlist stricte : is_admin n'est PAS exposé"""
    class Meta:
        unknown = RAISE  # ✅ Rejette les champs non déclarés

    email = fields.Email(required=True, validate=validate.Length(max=120))
    username = fields.String(
        required=True,
        validate=[
            validate.Length(min=3, max=80),
            validate.Regexp(r'^[a-zA-Z0-9_-]+$',
                            error="Username: alphanumeric, _ or - only")
        ]
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=8, max=128),
        load_only=True
    )
    bio = fields.String(load_default='', validate=validate.Length(max=500))
    csrf_token = fields.String(load_only=True, load_default='')


class LoginSchema(Schema):
    class Meta:
        unknown = RAISE

    email = fields.Email(required=True)
    password = fields.String(required=True, load_only=True)
    csrf_token = fields.String(load_only=True, load_default='')


class ProfileUpdateSchema(Schema):
    """✅ Seuls username et bio modifiables - PAS is_admin ni email"""
    class Meta:
        unknown = RAISE

    username = fields.String(
        validate=[
            validate.Length(min=3, max=80),
            validate.Regexp(r'^[a-zA-Z0-9_-]+$')
        ]
    )
    bio = fields.String(validate=validate.Length(max=500))
    csrf_token = fields.String(load_only=True, load_default='')


class CommentSchema(Schema):
    class Meta:
        unknown = RAISE

    content = fields.String(required=True, validate=validate.Length(min=1, max=2000))
    csrf_token = fields.String(load_only=True, load_default='')


class PingSchema(Schema):
    class Meta:
        unknown = RAISE

    # ✅ Validation stricte : hostname ou IP uniquement
    host = fields.String(
        required=True,
        validate=validate.Regexp(
            r'^[a-zA-Z0-9.-]{1,253}$',
            error="Invalid hostname"
        )
    )
    csrf_token = fields.String(load_only=True, load_default='')
