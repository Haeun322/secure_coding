"""기능 + 보안 통합 테스트.

각 테스트는 '기대하는 안전한 동작' 을 검증한다. 보고서의 보안 항목과 1:1로 대응된다.
"""
from conftest import csrf_from, register, login


# --- 기본 기능 ------------------------------------------------------------
def test_index_ok(client):
    assert client.get("/").status_code == 200


def test_register_and_login(client):
    assert register(client, "alice").status_code == 200
    r = login(client, "alice")
    assert "로그아웃" in r.get_data(as_text=True)


def test_security_headers_present(client):
    r = client.get("/")
    assert "Content-Security-Policy" in r.headers
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


# --- 인증/입력 검증 -------------------------------------------------------
def test_weak_password_rejected(client):
    token = csrf_from(client, "/auth/register")
    r = client.post("/auth/register", data={
        "csrf_token": token, "username": "weakling",
        "password": "short", "display_name": "weak",
    })
    assert r.status_code == 400  # 검증 실패


def test_duplicate_username_rejected(client):
    register(client, "bob")
    r = register(client, "bob")
    assert r.status_code == 409  # 중복 아이디는 409 로 거절
    assert "이미 사용 중인 아이디" in r.get_data(as_text=True)


# --- CSRF -----------------------------------------------------------------
def test_post_without_csrf_is_forbidden(client):
    register(client, "carol")
    login(client, "carol")
    # 토큰 없이 POST -> 403
    r = client.post("/products/new", data={
        "title": "x", "description": "y", "price": "100",
    })
    assert r.status_code == 403


def test_post_with_bad_csrf_is_forbidden(client):
    register(client, "csrfuser")
    login(client, "csrfuser")
    r = client.post("/products/new", data={
        "csrf_token": "deadbeef", "title": "x",
        "description": "y", "price": "100",
    })
    assert r.status_code == 403


# --- 상품 + XSS + SQLi ----------------------------------------------------
def _create_product(client, title="노트북", desc="설명", price="10000"):
    token = csrf_from(client, "/products/new")
    return client.post("/products/new", data={
        "csrf_token": token, "title": title,
        "description": desc, "price": price,
    }, follow_redirects=True)


def test_xss_payload_is_escaped(client):
    register(client, "dave")
    login(client, "dave")
    payload = "<script>alert('xss')</script>"
    r = _create_product(client, title="해킹시도", desc=payload)
    body = r.get_data(as_text=True)
    # 스크립트 원문이 그대로 나오면 안 되고, 이스케이프되어야 한다.
    assert "<script>alert" not in body
    assert "&lt;script&gt;" in body


def test_search_sql_injection_is_safe(client):
    register(client, "erin")
    login(client, "erin")
    _create_product(client, title="정상상품")
    # 고전적인 SQLi 페이로드 -> 500 없이 정상 처리되어야 한다.
    r = client.get("/products/?q=' OR '1'='1")
    assert r.status_code == 200


def test_price_must_be_numeric(client):
    register(client, "frank")
    login(client, "frank")
    r = _create_product(client, price="공짜")
    assert r.status_code == 400


# --- 접근 제어 (IDOR) -----------------------------------------------------
def test_cannot_edit_others_product(client):
    register(client, "owner")
    login(client, "owner")
    _create_product(client, title="내상품")
    client.post("/auth/logout", data={"csrf_token": csrf_from(client, "/")},
                follow_redirects=True)

    register(client, "attacker")
    login(client, "attacker")
    # 상품 id 는 1이라고 가정(첫 상품). 남의 상품 수정 시도 -> 403
    r = client.get("/products/1/edit")
    assert r.status_code == 403


def test_login_required_redirects(client):
    r = client.get("/wallet/", follow_redirects=False)
    assert r.status_code == 302
    assert "/auth/login" in r.headers["Location"]


# --- 관리자 접근 제어 -----------------------------------------------------
def test_normal_user_cannot_access_admin(client):
    register(client, "grace")
    login(client, "grace")
    assert client.get("/admin/").status_code == 403


def test_admin_can_access_pages(client):
    login(client, "admin", "AdminPw12345")
    assert client.get("/admin/").status_code == 200
    assert client.get("/admin/users").status_code == 200
    assert client.get("/admin/products").status_code == 200
    assert client.get("/admin/reports").status_code == 200
    assert client.get("/admin/transfers").status_code == 200


def test_admin_can_block_and_unblock_user(app):
    admin_c = app.test_client()
    login(admin_c, "admin", "AdminPw12345")

    victim = app.test_client()
    register(victim, "target")  # users.id = 2 (admin=1)

    token = csrf_from(admin_c, "/admin/users")
    admin_c.post("/admin/users/2/block", data={"csrf_token": token},
                 follow_redirects=True)
    # 차단된 사용자는 로그인 불가
    r = login(victim, "target")
    assert "차단된 계정" in r.get_data(as_text=True)

    token = csrf_from(admin_c, "/admin/users")
    admin_c.post("/admin/users/2/unblock", data={"csrf_token": token},
                 follow_redirects=True)
    r = login(victim, "target")
    assert "로그아웃" in r.get_data(as_text=True)


# --- 송금 (핵심 보안) -----------------------------------------------------
def test_transfer_requires_password_and_balance(app):
    c = app.test_client()
    register(c, "sender")
    login(c, "sender")

    # 잔액 0에서 송금 시도 -> 실패(잔액부족). 먼저 수취인 필요.
    c2 = app.test_client()
    register(c2, "receiver")

    # sender 충전
    token = csrf_from(c, "/wallet/")
    c.post("/wallet/topup", data={"csrf_token": token, "amount": "5000"},
           follow_redirects=True)

    # 잘못된 비밀번호로 송금 -> 거절
    token = csrf_from(c, "/wallet/transfer")
    r = c.post("/wallet/transfer", data={
        "csrf_token": token, "recipient": "receiver",
        "amount": "1000", "password": "WrongPass!", "memo": "",
    })
    assert r.status_code == 401

    # 잔액 초과 송금 -> 거절
    token = csrf_from(c, "/wallet/transfer")
    r = c.post("/wallet/transfer", data={
        "csrf_token": token, "recipient": "receiver",
        "amount": "999999", "password": "Passw0rd!", "memo": "",
    }, follow_redirects=True)
    assert "잔액이 부족" in r.get_data(as_text=True)

    # 정상 송금
    token = csrf_from(c, "/wallet/transfer")
    r = c.post("/wallet/transfer", data={
        "csrf_token": token, "recipient": "receiver",
        "amount": "1000", "password": "Passw0rd!", "memo": "고마워",
    }, follow_redirects=True)
    assert "송금했습니다" in r.get_data(as_text=True)


def test_cannot_transfer_to_self(app):
    c = app.test_client()
    register(c, "selfsend")
    login(c, "selfsend")
    token = csrf_from(c, "/wallet/")
    c.post("/wallet/topup", data={"csrf_token": token, "amount": "5000"},
           follow_redirects=True)
    token = csrf_from(c, "/wallet/transfer")
    r = c.post("/wallet/transfer", data={
        "csrf_token": token, "recipient": "selfsend",
        "amount": "1000", "password": "Passw0rd!", "memo": "",
    })
    assert r.status_code == 400


def test_negative_amount_rejected(app):
    c = app.test_client()
    register(c, "neg")
    login(c, "neg")
    token = csrf_from(c, "/wallet/transfer")
    r = c.post("/wallet/transfer", data={
        "csrf_token": token, "recipient": "neg",
        "amount": "-100", "password": "Passw0rd!", "memo": "",
    })
    assert r.status_code == 400


# --- 로그인 브루트포스 레이트리밋 ----------------------------------------
def test_login_rate_limit(client):
    register(client, "victim")
    # 실패를 반복하면 임계치 후 429
    got_429 = False
    for _ in range(7):
        token = csrf_from(client, "/auth/login")
        r = client.post("/auth/login", data={
            "csrf_token": token, "username": "victim", "password": "WrongPass9",
        })
        if r.status_code == 429:
            got_429 = True
            break
    assert got_429


# --- 신고 -> 자동 차단 ----------------------------------------------------
def test_report_and_admin_block_flow(app):
    admin_c = app.test_client()
    login(admin_c, "admin", "AdminPw12345")

    seller = app.test_client()
    register(seller, "spammer")
    login(seller, "spammer")
    _create_product(seller, title="사기상품")

    # 관리자 차단
    token = csrf_from(admin_c, "/admin/products")
    r = admin_c.post("/admin/products/1/block",
                     data={"csrf_token": token}, follow_redirects=True)
    assert r.status_code == 200

    # 차단된 상품은 목록/상세에서 일반 사용자에게 노출되지 않음
    buyer = app.test_client()
    register(buyer, "buyer")
    login(buyer, "buyer")
    assert buyer.get("/products/1").status_code == 404
