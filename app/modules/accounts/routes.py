"""
ForensiX Accounts & User Administration Routes.
Implements secure login, TOTP MFA verification, password management,
and Admin user provisioning with CSRF protection and rate limiting.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    current_app,
)
from flask_login import login_user, logout_user, login_required, current_user

from app.db import query_db, execute_db
from app.security.auth import load_user
from app.security.rbac import role_required
from app.security.limits import limiter
from app.security.mfa import (
    generate_mfa_secret,
    get_provisioning_uri,
    generate_qr_code_svg,
    verify_totp_code,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    generate_backup_codes,
)
from app.modules.accounts.service import (
    authenticate_credentials,
    create_user,
    list_all_users,
    toggle_user_active_status,
    reset_user_password,
    update_user_role,
)
from app.modules.custody.service import append as custody_append

accounts_bp = Blueprint("accounts", __name__, template_folder="../../templates")


@accounts_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute")
def login():
    """User authentication endpoint with Argon2id and rate limiting."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user, err = authenticate_credentials(username, password)
        if err or not user:
            current_app.logger.warning(f"Failed login attempt for username '{username}'.")
            target_row = query_db("SELECT id, failed_attempts FROM users WHERE username = ?", (username,), one=True)
            user_id = target_row["id"] if target_row else None
            is_locked = bool(target_row and target_row["failed_attempts"] >= 5)
            action = "USER_LOCKED" if is_locked else "LOGIN_FAILED"
            custody_append(
                case_id=None,
                evidence_id=None,
                user_id=user_id,
                action=action,
                detail={"username": username, "reason": err or "Invalid credentials"},
            )
            flash(err or "Invalid username or password.", "error")
            return render_template("accounts/login.html")

        # Check if user requires MFA
        row = query_db("SELECT mfa_secret_enc, mfa_enabled FROM users WHERE id = ?", (user.id,), one=True)
        has_mfa = bool(row and row["mfa_enabled"] and row["mfa_secret_enc"])

        # Admin and Lead roles require mandatory MFA
        if has_mfa:
            session["pending_mfa_user_id"] = user.id
            return redirect(url_for("accounts.mfa_verify"))

        # If Lead or Admin lacks MFA, warn them but allow login or redirect to setup
        # Regenerate session ID to prevent session fixation attacks
        session.clear()
        login_user(user, remember=False)
        current_app.logger.info(f"User '{user.username}' logged in successfully.")
        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=user.id,
            action="USER_LOGIN",
            detail={"username": user.username, "mfa": False},
        )

        if user.role in ("Admin", "Lead") and not has_mfa:
            flash("MFA is required for your role. Please configure TOTP immediately.", "warning")
            return redirect(url_for("accounts.account"))

        next_url = request.args.get("next")
        return redirect(next_url or url_for("dashboard.index"))

    return render_template("accounts/login.html")


@accounts_bp.route("/mfa", methods=["GET", "POST"])
@limiter.limit("10/minute")
def mfa_verify():
    """Two-factor authentication code challenge."""
    pending_user_id = session.get("pending_mfa_user_id")
    if not pending_user_id:
        return redirect(url_for("accounts.login"))

    user = load_user(str(pending_user_id))
    if not user:
        session.pop("pending_mfa_user_id", None)
        return redirect(url_for("accounts.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        row = query_db("SELECT mfa_secret_enc FROM users WHERE id = ?", (user.id,), one=True)

        if not row or not row["mfa_secret_enc"]:
            flash("MFA configuration missing. Please log in again.", "error")
            return redirect(url_for("accounts.login"))

        try:
            secret = decrypt_mfa_secret(row["mfa_secret_enc"])
        except Exception:
            flash("Error decrypting MFA secret.", "error")
            return redirect(url_for("accounts.login"))

        if not verify_totp_code(secret, code):
            flash("Invalid or expired 6-digit verification code.", "error")
            return render_template("accounts/mfa.html")

        # TOTP successful: finalize authentication
        session.pop("pending_mfa_user_id", None)
        session.clear()
        login_user(user, remember=False)
        current_app.logger.info(f"User '{user.username}' completed MFA authentication successfully.")
        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=user.id,
            action="USER_LOGIN",
            detail={"username": user.username, "mfa": True},
        )
        return redirect(url_for("dashboard.index"))

    return render_template("accounts/mfa.html")


@accounts_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    """Clear session and log out."""
    uid = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else "unknown"
    custody_append(
        case_id=None,
        evidence_id=None,
        user_id=uid,
        action="USER_LOGOUT",
        detail={"username": username},
    )
    logout_user()
    session.clear()
    current_app.logger.info(f"User '{username}' logged out.")
    return redirect(url_for("accounts.login"))


@accounts_bp.route("/account", methods=["GET"])
@login_required
def account():
    """View user account details and MFA status."""
    row = query_db(
        "SELECT mfa_enabled, sign_pub_key, created_at FROM users WHERE id = ?",
        (current_user.id,),
        one=True,
    )
    return render_template(
        "accounts/account.html",
        active_nav="account",
        user_info=row,
    )


@accounts_bp.route("/account/mfa/setup", methods=["POST"])
@login_required
def mfa_setup():
    """Initiate TOTP MFA enrollment and render offline QR code."""
    secret = generate_mfa_secret()
    session["unconfirmed_mfa_secret"] = secret

    uri = get_provisioning_uri(current_user.username, secret)
    qr_data_uri = generate_qr_code_svg(uri)

    return render_template(
        "accounts/mfa_enroll.html",
        secret=secret,
        qr_code_data=qr_data_uri,
    )


@accounts_bp.route("/account/mfa/confirm", methods=["POST"])
@login_required
def mfa_confirm():
    """Confirm TOTP token, store encrypted secret, and generate backup codes."""
    unconfirmed_secret = session.get("unconfirmed_mfa_secret")
    if not unconfirmed_secret:
        flash("MFA session expired. Please start enrollment again.", "error")
        return redirect(url_for("accounts.account"))

    code = request.form.get("code", "").strip()
    if not verify_totp_code(unconfirmed_secret, code):
        flash("Invalid verification code. Please check your authenticator app and try again.", "error")
        return redirect(url_for("accounts.account"))

    # Generate backup codes and encrypt secret
    backup_codes, enc_backup = generate_backup_codes()
    enc_secret = encrypt_mfa_secret(unconfirmed_secret)

    execute_db(
        "UPDATE users SET mfa_secret_enc = ?, mfa_enabled = 1 WHERE id = ?",
        (enc_secret, current_user.id),
    )
    session.pop("unconfirmed_mfa_secret", None)
    current_app.logger.info(f"MFA successfully enabled for user '{current_user.username}'.")

    return render_template(
        "accounts/mfa_backup_codes.html",
        backup_codes=backup_codes,
    )


# ------------------------------------------------------------------------------
# Administrator User Management Routes (Admin Role Only)
# ------------------------------------------------------------------------------
@accounts_bp.route("/admin", methods=["GET"])
@role_required("Admin")
def admin_root():
    """Redirect /admin to user accounts list."""
    return redirect(url_for("accounts.admin_users_list"))


@accounts_bp.route("/admin/users", methods=["GET"])
@role_required("Admin")
def admin_users_list():
    """List all platform accounts."""
    users = list_all_users()
    return render_template(
        "accounts/admin_users.html",
        active_nav="system",
        users=users,
    )


@accounts_bp.route("/admin/users/create", methods=["POST"])
@role_required("Admin")
def admin_create_user():
    """Create a new user account."""
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "").strip()
    password = request.form.get("password", "")

    try:
        user_id = create_user(name, username, role, password)
        current_app.logger.info(f"Admin '{current_user.username}' created new user '{username}' ({role}).")
        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=current_user.id,
            action="USER_CREATED",
            detail={"created_user_id": user_id, "username": username, "role": role},
        )
        flash(f"User '{username}' created successfully.", "success")
    except ValueError as e:
        flash(str(e), "error")

    return redirect(url_for("accounts.admin_users_list"))


@accounts_bp.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@role_required("Admin")
def admin_toggle_user(user_id: int):
    """Toggle user active / deactivated status."""
    if user_id == current_user.id:
        flash("You cannot deactivate your own administrative account.", "error")
        return redirect(url_for("accounts.admin_users_list"))

    try:
        new_status = toggle_user_active_status(user_id)
        status_label = "activated" if new_status else "deactivated"
        current_app.logger.info(f"Admin '{current_user.username}' {status_label} user ID {user_id}.")
        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=current_user.id,
            action="USER_STATUS_TOGGLED",
            detail={"target_user_id": user_id, "active": new_status},
        )
        flash(f"User ID {user_id} has been {status_label}.", "success")
    except ValueError as e:
        flash(str(e), "error")

    return redirect(url_for("accounts.admin_users_list"))


@accounts_bp.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@role_required("Admin")
def admin_reset_password(user_id: int):
    """Reset a user's password."""
    new_password = request.form.get("new_password", "")
    try:
        reset_user_password(user_id, new_password)
        current_app.logger.info(f"Admin '{current_user.username}' reset password for user ID {user_id}.")
        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=current_user.id,
            action="PASSWORD_RESET",
            detail={"target_user_id": user_id},
        )
        flash("Password successfully reset.", "success")
    except ValueError as e:
        flash(str(e), "error")

    return redirect(url_for("accounts.admin_users_list"))


@accounts_bp.route("/admin/users/<int:user_id>/change-role", methods=["POST"])
@role_required("Admin")
def admin_change_role(user_id: int):
    """Update a user's role."""
    new_role = request.form.get("new_role", "")
    try:
        update_user_role(user_id, new_role)
        current_app.logger.info(f"Admin '{current_user.username}' updated user ID {user_id} role to '{new_role}'.")
        custody_append(
            case_id=None,
            evidence_id=None,
            user_id=current_user.id,
            action="ROLE_CHANGED",
            detail={"target_user_id": user_id, "new_role": new_role},
        )
        flash(f"User role updated to '{new_role}'.", "success")
    except ValueError as e:
        flash(str(e), "error")

    return redirect(url_for("accounts.admin_users_list"))
