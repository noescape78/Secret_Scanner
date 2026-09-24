"""
sample.py - Test file containing FAKE credentials for testing Secret Scanner.

IMPORTANT: All keys, tokens, and passwords in this file are completely FAKE
and intended solely for demonstration and test verification.
"""

# 1. AWS Access Key (Fake AWS standard example key)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# 2. GitHub Personal Access Token (Fake dummy token)
GITHUB_TOKEN = "ghp_FAKEGITHUBTOKEN1234567890abcdefghijkl"

# 3. Hardcoded Password
DATABASE_PASSWORD = "FakeAdminPassword2026!"

# 4. API Key Assignment
PAYMENT_API_KEY = "sk_live_FAKEAPIKEY123456789ABC"

# 5. JSON Web Token (JWT) (Standard RFC 7519 dummy JWT)
USER_SESSION_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# 6. Database Connection String with credentials
DB_CONNECTION_STRING = "postgres://fake_db_user:fake_super_secret_pwd@db.internal:5432/production_db"

# 7. Secret Key Assignment
CLIENT_SECRET_KEY = "secret_key_FAKECLIENTSECRET9876543210"

# 8. Access Token Assignment
OAUTH_ACCESS_TOKEN = "access_token_FAKEACCESSTOKEN_ABCDEF123456789"

# 9. Generic API Token
SERVICE_TOKEN = "tok_FAKETOKENVALUE555666777888999"

# 10. Private Key Header Simulation (Commented demo block)
FAKE_PRIVATE_KEY_BLOCK = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3Ffake...example...only...
-----END RSA PRIVATE KEY-----
"""


def connect_service():
    """Dummy function simulating an external API request."""
    print("Connecting using test credentials...")
