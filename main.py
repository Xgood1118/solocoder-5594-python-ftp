import sys
import signal

from audit_logger import AuditLogger
from ftp_server import create_server
from user_manager import UserManager

import config


def init_default_users():
    um = UserManager()
    if um.get_user("admin") is None:
        um.add_user(
            username="admin",
            password="admin123",
            permissions="rwda",
            quota_bytes=1024**3,
        )
        print("[INIT] Created admin user (password: admin123, quota: 1GB, perms: rwda)")
    else:
        print("[INIT] admin user already exists")

    if um.get_user("dev1") is None:
        um.add_user(
            username="dev1",
            password="dev1123",
            permissions="rwd",
            quota_bytes=500 * 1024**2,
        )
        print("[INIT] Created dev1 user (password: dev1123, quota: 500MB, perms: rwd)")
    else:
        print("[INIT] dev1 user already exists")

    if um.get_user("readonly") is None:
        um.add_user(
            username="readonly",
            password="readonly123",
            permissions="r",
            quota_bytes=100 * 1024**2,
        )
        print("[INIT] Created readonly user (password: readonly123, quota: 100MB, perms: r)")
    else:
        print("[INIT] readonly user already exists")


def main():
    print("=" * 60)
    print("  FTP Server - Internal File Transfer Service")
    print("=" * 60)

    init_default_users()

    audit = AuditLogger()
    audit.start_archiver(interval_hours=24)
    print("[AUDIT] Log archiver started (interval: 24h)")

    server = create_server()
    print(f"[SERVER] Listening on {config.FTP_HOST}:{config.FTP_PORT}")
    print(f"[SERVER] Passive ports: {config.FTP_PASSIVE_PORTS.start}-{config.FTP_PASSIVE_PORTS.stop}")
    print(f"[SERVER] Chunk threshold: {config.CHUNK_THRESHOLD / (1024*1024):.0f}MB")
    print(f"[SERVER] Max login attempts: {config.MAX_LOGIN_ATTEMPTS}, lockout: {config.LOCKOUT_DURATION}s")
    print("=" * 60)
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    def shutdown(signum, frame):
        print("\n[SERVER] Shutting down...")
        server.close_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    finally:
        server.close_all()


if __name__ == "__main__":
    main()
