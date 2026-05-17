"""Helpers de sécurité"""
import os
import re
import ipaddress
import bleach
from functools import wraps
from flask import abort, request, current_app
from flask_login import current_user


# ===== Sanitization HTML =====

ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li']
ALLOWED_ATTRS = {'a': ['href', 'title']}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


def sanitize_html(content: str) -> str:
    """✅ Nettoie le HTML utilisateur avec une allowlist stricte"""
    if not content:
        return ''
    return bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_PROTOCOLS,
        strip=True
    )


# ===== Décorateurs d'autorisation =====

def admin_required(f):
    """✅ Vérification rôle admin"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin:
            current_app.logger.warning(
                f"Unauthorized admin access attempt by user_id={current_user.id} "
                f"from IP={request.remote_addr}"
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated


def owns_resource(model, id_param='resource_id', owner_field='user_id'):
    """✅ Décorateur générique : vérifie la propriété d'une ressource"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            resource_id = kwargs.get(id_param)
            if resource_id is None:
                abort(400)
            resource = model.query.get_or_404(resource_id)
            if getattr(resource, owner_field) != current_user.id and not current_user.is_admin:
                current_app.logger.warning(
                    f"IDOR attempt: user={current_user.id} on {model.__name__}={resource_id}"
                )
                abort(403)
            kwargs['resource'] = resource
            return f(*args, **kwargs)
        return decorated
    return decorator


# ===== Validation de chemins =====

def safe_path(base_dir: str, user_path: str) -> str | None:
    """✅ Protection path traversal : retourne None si traversée détectée"""
    if not user_path:
        return None
    # Refuser tout caractère suspect d'emblée
    if '..' in user_path or user_path.startswith('/') or user_path.startswith('\\'):
        return None

    base_real = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_real, user_path))

    # Vérifier que la cible reste dans base_dir
    if os.path.commonpath([base_real, target]) != base_real:
        return None
    return target


def allowed_file(filename: str, allowed_exts: set) -> bool:
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_exts


# ===== Validation host (pour ping) =====

HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')


def is_safe_host(host: str) -> bool:
    """✅ Valide qu'il s'agit d'un hostname ou d'une IP publique"""
    if not host or len(host) > 253:
        return False
    # Tenter IP
    try:
        ip = ipaddress.ip_address(host)
        # Refuser IPs privées / loopback / link-local pour éviter SSRF
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        pass
    # Sinon hostname
    return bool(HOSTNAME_RE.match(host))
