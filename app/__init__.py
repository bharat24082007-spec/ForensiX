"""
ForensiX Application Factory.
Initializes Flask app, database connection lifecycle, security controls,
authentication, CSRF protection, rate limiting, and structured logging.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, Optional
from flask import Flask, jsonify
from flask_wtf.csrf import CSRFProtect

from app.config import Config
from app.db import close_db, init_db
from app.logger import setup_logger
from app.security import login_manager, limiter, init_security_headers
from app.modules.dashboard import dashboard_bp
from app.modules.accounts import accounts_bp
from app.modules.cases import cases_bp
from app.modules.evidence import evidence_bp
from app.modules.custody import custody_bp
from app.modules.system import system_bp
from app.modules.metadata import metadata_bp
from app.modules.network import network_bp
from app.modules.logs import logs_bp
from app.modules.iocs import iocs_bp
from app.modules.timeline import timeline_bp
from app.modules.reports import reports_bp
from app.modules.graph import graph_bp
from app.adapters.registry import init_tool_registry

csrf = CSRFProtect()


def create_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    """Create and configure the ForensiX application instance."""
    app = Flask(__name__)

    if test_config is not None:
        config_obj = Config(env={k: str(v) for k, v in test_config.items()})
    else:
        config_obj = Config()

    # Populate standard config keys from validated Config object
    app.config["SECRET_KEY"] = config_obj.SECRET_KEY
    app.config["HOST"] = config_obj.HOST
    app.config["PORT"] = config_obj.PORT
    app.config["ALLOW_LAN"] = config_obj.ALLOW_LAN
    app.config["DATA_DIR"] = config_obj.DATA_DIR
    app.config["DB_DIR"] = config_obj.DB_DIR
    app.config["VAULT_DIR"] = config_obj.VAULT_DIR
    app.config["WORK_DIR"] = config_obj.WORK_DIR
    app.config["REPORTS_DIR"] = config_obj.REPORTS_DIR
    app.config["BACKUPS_DIR"] = config_obj.BACKUPS_DIR
    app.config["KEYS_DIR"] = config_obj.KEYS_DIR
    app.config["LOGS_DIR"] = config_obj.LOGS_DIR
    app.config["DATABASE_PATH"] = config_obj.DATABASE_PATH
    app.config["MASTER_KEY_PATH"] = config_obj.MASTER_KEY_PATH
    app.config["MAX_CONTENT_LENGTH"] = config_obj.MAX_CONTENT_LENGTH
    app.config["TSHARK_PATH"] = config_obj.TSHARK_PATH
    app.config["CAPINFOS_PATH"] = config_obj.CAPINFOS_PATH
    app.config["EXIFTOOL_PATH"] = config_obj.EXIFTOOL_PATH
    app.config["EXTERNAL_LOOKUPS"] = config_obj.EXTERNAL_LOOKUPS
    app.config["PUBLIC_VERIFY"] = config_obj.PUBLIC_VERIFY
    app.config["WATCHDOG_INTERVAL_MIN"] = config_obj.WATCHDOG_INTERVAL_MIN

    # Session cookie security settings (HttpOnly, SameSite=Strict, 30m idle timeout)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

    if test_config is not None:
        app.config.update(test_config)

    # Ensure all data subdirectories exist with appropriate permissions
    config_obj.ensure_directories()

    # Initialize structured JSON logger
    logger = setup_logger(config_obj.LOGS_DIR)
    app.logger = logger
    logger.info("ForensiX application initialized successfully.")

    # Register database context teardown
    app.teardown_appcontext(close_db)

    # Initialize Security Components
    csrf.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    init_security_headers(app)

    # Initialize Database Schema
    with app.app_context():
        init_db(config_obj.DATABASE_PATH)

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(accounts_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(custody_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(metadata_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(iocs_bp)
    app.register_blueprint(timeline_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(graph_bp)

    # Initialize External Forensic Tool Registry
    init_tool_registry(app)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify(
            {
                "status": "operational",
                "app": "ForensiX",
                "host_mode": "loopback" if config_obj.is_loopback(config_obj.HOST) else "lan",
                "storage_initialized": True,
            }
        )

    return app
