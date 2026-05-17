"""Configuration de logs structurés JSON"""
import logging
import json
from datetime import datetime
from flask import request, has_request_context


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if has_request_context():
            log.update({
                'ip': request.remote_addr,
                'method': request.method,
                'path': request.path,
                'user_agent': request.headers.get('User-Agent', '')[:200],
            })
        if record.exc_info:
            log['exception'] = self.formatException(record.exc_info)
        return json.dumps(log)


def configure_logging(app):
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(app.config.get('LOG_LEVEL', 'INFO'))

    # Capter aussi les logs Werkzeug
    logging.getLogger('werkzeug').addHandler(handler)
