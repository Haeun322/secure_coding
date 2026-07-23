"""pytest 공용 픽스처.

매 테스트마다 임시 폴더에 새 SQLite DB 를 만들어 서로 간섭하지 않게 한다.
"""
import os
import re
import sys
import tempfile

import pytest

# 프로젝트 루트를 import 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402


@pytest.fixture
def app():
    tmpdir = tempfile.mkdtemp()
    test_config = {
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "INSTANCE_DIR": tmpdir,
        "DATABASE": os.path.join(tmpdir, "test.sqlite3"),
        "UPLOAD_DIR": os.path.join(tmpdir, "uploads"),
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": "AdminPw12345",
        "SESSION_COOKIE_SECURE": False,
    }
    application = create_app(test_config)
    # 메모리 기반 레이트리밋 버킷은 프로세스 전역이므로 테스트 간 초기화한다.
    from app import security
    security._rate_buckets.clear()
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


# --- 헬퍼 -----------------------------------------------------------------
_CSRF_RE = re.compile(r'name="csrf_token" value="([0-9a-f]+)"')


def csrf_from(client, path):
    """GET 으로 폼 페이지를 받아 CSRF 토큰을 추출."""
    html = client.get(path).get_data(as_text=True)
    m = _CSRF_RE.search(html)
    assert m, f"{path} 에서 CSRF 토큰을 찾지 못했습니다."
    return m.group(1)


def register(client, username, password="Passw0rd!", display=None):
    token = csrf_from(client, "/auth/register")
    return client.post("/auth/register", data={
        "csrf_token": token,
        "username": username,
        "password": password,
        "display_name": display or username,
    }, follow_redirects=True)


def login(client, username, password="Passw0rd!"):
    token = csrf_from(client, "/auth/login")
    return client.post("/auth/login", data={
        "csrf_token": token,
        "username": username,
        "password": password,
    }, follow_redirects=True)
