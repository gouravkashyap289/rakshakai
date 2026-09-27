import os
import tempfile
import pytest

_test_dir=tempfile.TemporaryDirectory(prefix='rakshak-test-')
os.environ['DATABASE_URL']='sqlite:///'+_test_dir.name.replace('\\','/')+'/test.db'
os.environ['ENABLE_NETWORK_LOOKUPS']='false'
os.environ['TRUSTED_AUTHSERV_IDS']=''
os.environ['RAKSHAK_API_KEY']=''

@pytest.fixture(autouse=True)
def isolated_rate_limit():
    from app.main import app, SecurityMiddleware
    layer=app.middleware_stack
    while layer is not None:
        if isinstance(layer,SecurityMiddleware): layer.hits.clear()
        layer=getattr(layer,'app',None)

def pytest_sessionfinish(session,exitstatus):
    from app.database import engine
    engine.dispose()
    _test_dir.cleanup()
