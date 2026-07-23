"""리뷰에서 발견한 결함들에 대한 회귀 테스트.

각 테스트는 '고친 뒤에는 이렇게 동작해야 한다'를 고정한다.
"""
import os
import sqlite3

import pytest

from conftest import csrf_from, register, login


def _seed_balance(app, username, balance):
    """테스트 편의: DB 를 직접 만져 잔액을 세팅."""
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("UPDATE users SET balance = ? WHERE username = ?", (balance, username))
    conn.commit()
    conn.close()


def _create_product(client, title="상품", desc="설명", price="1000"):
    token = csrf_from(client, "/products/new")
    return client.post("/products/new", data={
        "csrf_token": token, "title": title, "description": desc, "price": price,
    }, follow_redirects=True)


# --- 차단된 상품 되살리기(모더레이션 우회) 방지 -----------------------------
def test_owner_cannot_unblock_blocked_product_via_edit(app):
    admin_c = app.test_client()
    login(admin_c, "admin", "AdminPw12345")

    seller = app.test_client()
    register(seller, "seller1")
    login(seller, "seller1")
    _create_product(seller, title="문제상품")  # product id 1

    # 관리자가 차단
    admin_c.post("/admin/products/1/block",
                 data={"csrf_token": csrf_from(admin_c, "/admin/products")},
                 follow_redirects=True)

    # 소유자가 편집으로 status=active 되살리기 시도
    r = seller.post("/products/1/edit", data={
        "csrf_token": csrf_from(seller, "/products/1"),  # detail 페이지에서 토큰
        "title": "문제상품", "description": "설명", "price": "1000", "status": "active",
    }, follow_redirects=True)

    # 여전히 차단 상태여야 한다 -> 구매자에게 404
    buyer = app.test_client()
    register(buyer, "buyer1")
    login(buyer, "buyer1")
    assert buyer.get("/products/1").status_code == 404


# --- 오픈 리다이렉트(역슬래시 우회) 방지 ------------------------------------
def test_open_redirect_backslash_blocked(client):
    register(client, "redir")
    token = csrf_from(client, "/auth/login")
    r = client.post("/auth/login?next=/%5Cevil.com", data={
        "csrf_token": token, "username": "redir", "password": "Passw0rd!",
    }, follow_redirects=False)
    # 로그인 성공 시 리다이렉트되지만, 외부(evil.com)로는 절대 가지 않아야 한다.
    loc = r.headers.get("Location", "")
    assert "evil.com" not in loc


# --- 계정 잠금 DoS 방지: 피해자는 자기 IP 에서 여전히 로그인 가능 -----------
def test_account_lockout_does_not_affect_victim_own_ip(app):
    victim = app.test_client()
    register(victim, "victim2")

    # 공격자(다른 IP)가 victim2 계정으로 반복 실패
    attacker = app.test_client()
    blocked = False
    for _ in range(8):
        token = csrf_from(attacker, "/auth/login")
        r = attacker.post("/auth/login", data={
            "csrf_token": token, "username": "victim2", "password": "WrongPw123",
        }, environ_base={"REMOTE_ADDR": "9.9.9.9"})
        if r.status_code == 429:
            blocked = True
            break
    assert blocked, "공격자 IP 는 결국 차단되어야 한다"

    # 피해자는 자신의 IP(127.0.0.1)에서 정상 로그인되어야 한다
    r = login(victim, "victim2")
    assert "로그아웃" in r.get_data(as_text=True)


# --- 차단 계정 열거 방지: 틀린 비밀번호엔 일반 메시지 ------------------------
def test_blocked_account_not_enumerable_with_wrong_password(app):
    admin_c = app.test_client()
    login(admin_c, "admin", "AdminPw12345")
    victim = app.test_client()
    register(victim, "blkuser")  # id 2
    admin_c.post("/admin/users/2/block",
                 data={"csrf_token": csrf_from(admin_c, "/admin/users")},
                 follow_redirects=True)

    # 틀린 비밀번호 -> 차단 사실을 알려주면 안 됨(일반 메시지)
    guesser = app.test_client()
    token = csrf_from(guesser, "/auth/login")
    r = guesser.post("/auth/login", data={
        "csrf_token": token, "username": "blkuser", "password": "TotallyWrong9",
    })
    body = r.get_data(as_text=True)
    assert "차단된 계정" not in body
    assert "올바르지 않습니다" in body

    # 맞는 비밀번호 -> 본인에게는 차단 사유 안내(403)
    token = csrf_from(victim, "/auth/login")
    r = victim.post("/auth/login", data={
        "csrf_token": token, "username": "blkuser", "password": "Passw0rd!",
    })
    assert r.status_code == 403
    assert "차단된 계정" in r.get_data(as_text=True)


# --- topup 총액 한도 ------------------------------------------------------
def test_topup_total_balance_cap(app):
    c = app.test_client()
    register(c, "rich")
    login(c, "rich")
    _seed_balance(app, "rich", 9_600_000)  # 한도(1천만) 근처로 세팅

    token = csrf_from(c, "/wallet/")
    r = c.post("/wallet/topup", data={"csrf_token": token, "amount": "500000"},
               follow_redirects=True)
    assert "한도" in r.get_data(as_text=True)

    # 잔액은 그대로여야 한다
    conn = sqlite3.connect(app.config["DATABASE"])
    bal = conn.execute("SELECT balance FROM users WHERE username='rich'").fetchone()[0]
    conn.close()
    assert bal == 9_600_000


# --- 상품 삭제 시 고아 신고 정리 -------------------------------------------
def test_reports_cleaned_on_product_delete(app):
    seller = app.test_client()
    register(seller, "seller3")
    login(seller, "seller3")
    _create_product(seller, title="삭제될상품")  # id 1

    reporter = app.test_client()
    register(reporter, "reporter1")
    login(reporter, "reporter1")
    reporter.post("/report/product/1",
                  data={"csrf_token": csrf_from(reporter, "/report/product/1"),
                        "reason": "가짜입니다"}, follow_redirects=True)

    # 소유자가 삭제(차단 안 된 상태라 삭제 가능)
    seller.post("/products/1/delete",
                data={"csrf_token": csrf_from(seller, "/products/1")},
                follow_redirects=True)

    conn = sqlite3.connect(app.config["DATABASE"])
    n = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE target_type='product' AND target_id=1"
    ).fetchone()[0]
    conn.close()
    assert n == 0


# --- 페이지네이션 --------------------------------------------------------
def test_pagination(app):
    c = app.test_client()
    register(c, "seller4")
    login(c, "seller4")
    for i in range(13):  # PAGE_SIZE=12 -> 2페이지
        _create_product(c, title=f"물건{i}")

    r1 = c.get("/products/?page=1")
    assert "1 / 2" in r1.get_data(as_text=True)
    r2 = c.get("/products/?page=2")
    assert r2.status_code == 200
    # 잘못된 page 값도 안전하게 처리
    assert c.get("/products/?page=-5").status_code == 200
    assert c.get("/products/?page=abc").status_code == 200


# --- 보안 헤더 강화 확인 --------------------------------------------------
def test_csp_and_hsts_headers(client):
    r = client.get("/")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "object-src 'none'" in csp
    assert "style-src 'self'" in csp
    # 개발(비-HTTPS)에서는 HSTS 를 보내지 않는다
    assert "Strict-Transport-Security" not in r.headers
    # 외부 JS 파일이 정상 서빙되는지
    assert client.get("/static/app.js").status_code == 200


# --- 비밀번호 정책 --------------------------------------------------------
def test_common_password_rejected(client):
    token = csrf_from(client, "/auth/register")
    r = client.post("/auth/register", data={
        "csrf_token": token, "username": "weakpw",
        "password": "password1", "display_name": "weak",
    })
    assert r.status_code == 400


def test_username_in_password_rejected(client):
    token = csrf_from(client, "/auth/register")
    r = client.post("/auth/register", data={
        "csrf_token": token, "username": "myname",
        "password": "myname1234", "display_name": "n",
    })
    assert r.status_code == 400


# --- 동시성: 이중지불 방지 -------------------------------------------------
def test_concurrent_transfers_no_double_spend(app):
    """잔액 1000원인 사용자가 동시에 1000원 송금 10건을 시도해도
    성공은 정확히 1건, 잔액은 절대 음수가 되지 않아야 한다."""
    import threading
    from app.blueprints.payments import _do_transfer
    from app.db import get_write_connection

    with app.app_context():
        db = get_write_connection()
        db.execute("INSERT INTO users (username,password_hash,display_name,balance)"
                   " VALUES ('cs','x','cs',1000)")
        db.execute("INSERT INTO users (username,password_hash,display_name,balance)"
                   " VALUES ('cr','x','cr',0)")
        sid = db.execute("SELECT id FROM users WHERE username='cs'").fetchone()[0]
        rid = db.execute("SELECT id FROM users WHERE username='cr'").fetchone()[0]
        db.close()

    results = []
    lock = threading.Lock()

    def worker():
        with app.app_context():
            ok, _ = _do_transfer(sid, rid, 1000, "race")
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with app.app_context():
        db = get_write_connection()
        s = db.execute("SELECT balance FROM users WHERE id=?", (sid,)).fetchone()[0]
        r = db.execute("SELECT balance FROM users WHERE id=?", (rid,)).fetchone()[0]
        cnt = db.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        db.close()

    assert sum(1 for x in results if x) == 1   # 정확히 1건만 성공
    assert s == 0 and r == 1000                # 잔액 정확
    assert s >= 0                              # 절대 음수 불가
    assert cnt == 1                            # 원장도 1건


# --- 금액 파서 엄격성(단위 테스트) ----------------------------------------
def test_amount_parser_strictness():
    from app.validators import validate_amount

    assert validate_amount("1000") == 1000
    assert validate_amount("1,000") == 1000
    for bad in ["1,2,3", "１２３", "-1", "1.5", "0", "abc", "1e9", "  "]:
        with pytest.raises(ValueError):
            validate_amount(bad)
