import os

APP_NAME = os.getenv("APP_NAME", "IronClaw Gen1")
APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
APP_PORT = int(os.getenv("APP_PORT", "8000"))
REPORTS_DIR = os.getenv("REPORTS_DIR", "samples/reports")
UPLOADS_DIR = os.getenv("UPLOADS_DIR", "samples/uploads")
QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", "samples/quarantine")
