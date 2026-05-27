from __future__ import annotations

import os

# Hard-set all required env vars before ANY app module is imported.
# setdefault is insufficient — CI may have these unset or empty string.
os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["API_KEY"] = "test-api-key"
os.environ["IRONCLAW_SECRET_KEY"] = os.environ.get("IRONCLAW_SECRET_KEY") or "test-secret-key-32-chars-minimum!!"
os.environ["JWT_SECRET"] = os.environ.get("JWT_SECRET") or "test-jwt-secret-key-32-chars-min!"
os.environ["ALLOWED_ORIGINS"] = os.environ.get("ALLOWED_ORIGINS") or "http://testserver"
os.environ["SUPABASE_URL"] = os.environ.get("SUPABASE_URL") or ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or ""
os.environ["SUPABASE_KEY"] = os.environ.get("SUPABASE_KEY") or ""
os.environ["SUPABASE_ANON_KEY"] = os.environ.get("SUPABASE_ANON_KEY") or ""
