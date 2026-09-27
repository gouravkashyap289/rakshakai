import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_UPLOAD = 10 * 1024 * 1024

# Vercel Functions may only write to the operating system temporary directory.
# A configured PostgreSQL URL remains the production path; temporary SQLite is
# a functional preview fallback and is intentionally not advertised as durable.
default_db = Path(tempfile.gettempdir()) / 'rakshak.db' if os.getenv('VERCEL') else ROOT / 'rakshak.db'
DATABASE_URL = os.getenv('DATABASE_URL', f'sqlite:///{default_db}')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = 'postgresql+psycopg://' + DATABASE_URL.removeprefix('postgres://')
elif DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL = 'postgresql+psycopg://' + DATABASE_URL.removeprefix('postgresql://')

# Prefer the licensed local GeoLite2 copies when they are present in the
# deployment bundle. Explicit environment variables still take precedence.
for key, filename in (
    ('GEOLITE2_CITY_PATH', 'GeoLite2-City.mmdb'),
    ('GEOLITE2_ASN_PATH', 'GeoLite2-ASN.mmdb'),
):
    bundled = ROOT / 'data' / filename
    if bundled.is_file():
        os.environ.setdefault(key, str(bundled))

NETWORK_ENABLED = os.getenv('ENABLE_NETWORK_LOOKUPS', 'false').lower() == 'true'
TRUSTED_AUTHSERV = {x.strip().lower() for x in os.getenv('TRUSTED_AUTHSERV_IDS', '').split(',') if x.strip()}
API_KEY = os.getenv('RAKSHAK_API_KEY', '')
