"""
ForensiX Platform Main Entrypoint.
Starts the Waitress WSGI server on 127.0.0.1 in a single process.
Provides CLI command to provision the initial Administrator account.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Optional
from waitress import serve

from app import create_app
from app.config import Config
from app.db import init_db
from app.modules.accounts.service import create_user
from app.modules.integrity.watchdog import init_watchdog
from app.security.auth import validate_password_complexity


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ForensiX: Digital Forensic Investigation & Evidence Management Platform"
    )
    parser.add_argument(
        "--create-admin",
        action="store_true",
        help="Interactive creation of the initial administrator account (Section S2).",
    )
    parser.add_argument(
        "--admin-name",
        type=str,
        default="",
        help="Full name for Administrator (optional non-interactive setup).",
    )
    parser.add_argument(
        "--admin-username",
        type=str,
        default="",
        help="Username for Administrator (optional non-interactive setup).",
    )
    parser.add_argument(
        "--admin-password",
        type=str,
        default="",
        help="Password for Administrator (optional non-interactive setup).",
    )
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="Reset password for an existing user account.",
    )
    parser.add_argument(
        "--username",
        type=str,
        default="",
        help="Username of account to reset.",
    )
    parser.add_argument(
        "--new-password",
        type=str,
        default="",
        help="New password for account (min 12 chars, letters & digits).",
    )
    return parser.parse_args()


def _read_secret(prompt: str) -> str:
    """
    Prompt for password.
    On Windows interactive consoles, echoes asterisks ('*') for visual feedback.
    Falls back to getpass or line input when piped or non-Windows.
    """
    print(prompt, end="", flush=True)

    # Windows interactive console: provide asterisks feedback using msvcrt
    if os.name == "nt" and sys.stdin.isatty():
        try:
            import msvcrt
            chars = []
            while True:
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    print()
                    break
                elif ch == "\003":  # Ctrl+C
                    raise KeyboardInterrupt
                elif ch in ("\b", "\x7f"):  # Backspace
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\000" or ch == "\xe0":  # Function/Arrow keys prefix
                    msvcrt.getwch()  # Consume second byte
                else:
                    chars.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
            return "".join(chars)
        except Exception:
            pass

    # Standard POSIX / fallback TTY
    if sys.stdin.isatty():
        return getpass.getpass("")

    # Non-TTY / piped input
    line = sys.stdin.readline()
    return line.rstrip("\r\n")


def interactive_create_admin(app, args: Optional[argparse.Namespace] = None) -> None:
    """Interactively or via arguments provision the initial Administrator with Argon2id and Ed25519 keys."""
    print("\n--- ForensiX Initial Admin Setup ---")
    try:
        name = getattr(args, "admin_name", "") if args else ""
        username = getattr(args, "admin_username", "") if args else ""
        password = getattr(args, "admin_password", "") if args else ""

        if not name:
            if sys.stdin.isatty():
                name = input("Enter Admin Full Name: ").strip()
            else:
                print("Enter Admin Full Name: ", end="", flush=True)
                name = sys.stdin.readline().strip()

        if not username:
            if sys.stdin.isatty():
                username = input("Enter Admin Username: ").strip().lower()
            else:
                print("Enter Admin Username: ", end="", flush=True)
                username = sys.stdin.readline().strip().lower()

        if not name or not username:
            print("[!] Error: Name and username cannot be empty.", file=sys.stderr)
            sys.exit(1)

        if not password:
            password = _read_secret("Enter Admin Password (min 12 chars, letters & digits): ")
            confirm_password = _read_secret("Confirm Admin Password: ")
            if password != confirm_password:
                print("[!] Error: Passwords do not match.", file=sys.stderr)
                sys.exit(1)

        validate_password_complexity(password)

        with app.app_context():
            user_id = create_user(name, username, role="Admin", password=password)
            print(f"\n[+] Administrator '{username}' (ID: {user_id}) created successfully.")
            print("[+] Login at http://127.0.0.1:5000/login and configure TOTP MFA.\n")
            sys.exit(0)
    except (ValueError, KeyboardInterrupt) as e:
        print(f"\n[!] Setup cancelled or failed: {e}", file=sys.stderr)
        sys.exit(1)


def reset_password_cli(app, args: argparse.Namespace) -> None:
    """CLI handler to reset password for any existing account."""
    print("\n--- ForensiX Password Reset ---")
    username = (args.username or "").strip().lower()
    if not username:
        if sys.stdin.isatty():
            username = input("Enter username to reset password: ").strip().lower()
        else:
            print("Enter username to reset password: ", end="", flush=True)
            username = sys.stdin.readline().strip().lower()

    if not username:
        print("[!] Error: Username cannot be empty.", file=sys.stderr)
        sys.exit(1)

    password = getattr(args, "new_password", "")
    if not password:
        password = _read_secret("Enter New Password (min 12 chars, letters & digits): ")
        confirm_password = _read_secret("Confirm New Password: ")
        if password != confirm_password:
            print("[!] Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    try:
        validate_password_complexity(password)
    except ValueError as e:
        print(f"[!] Password policy error: {e}", file=sys.stderr)
        sys.exit(1)

    with app.app_context():
        from app.db import query_db
        user_row = query_db("SELECT id, username FROM users WHERE username = ?", (username,), one=True)
        if not user_row:
            print(f"[!] Error: User '{username}' does not exist.", file=sys.stderr)
            sys.exit(1)

        from app.modules.accounts.service import reset_user_password
        reset_user_password(user_row["id"], password)
        print(f"\n[+] Password for user '{username}' successfully reset.")
        print("[+] Login at http://127.0.0.1:5000/login\n")
        sys.exit(0)


def main() -> None:
    args = parse_arguments()

    # Load and validate configuration
    try:
        config = Config()
    except ValueError as e:
        print(f"\n[!] CONFIGURATION HALTED: {e}\n", file=sys.stderr)
        sys.exit(1)

    # Ensure required data folders are provisioned
    config.ensure_directories()

    # Create Flask app instance
    app = create_app()

    # Handle --create-admin flag
    if args.create_admin:
        interactive_create_admin(app, args)

    # Handle --reset-password flag
    if args.reset_password:
        reset_password_cli(app, args)

    banner = (
        "=" * 68 + "\n"
        f"  ForensiX Platform - Forensic Investigation System\n"
        f"  Server Binding : http://{config.HOST}:{config.PORT}\n"
        f"  Architecture   : Single-process in-process host (Waitress)\n"
        f"  Integrity Mode : Strict (Append-only custody, SHA-256 intake)\n"
        f"  Data Directory : {config.DATA_DIR}\n"
        "=" * 68
    )
    print(banner)

    # Initialize background evidence integrity watchdog
    init_watchdog(app, interval_minutes=config.WATCHDOG_INTERVAL_MIN)

    # Start single-process Waitress server
    serve(app, host=config.HOST, port=config.PORT, threads=4)


if __name__ == "__main__":
    main()
