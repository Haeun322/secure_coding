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


# --- 에스크로 결제 / 상품 가격 자동 결제 ----------------------------------
def _create_priced_product(client, price, title="상품", category="etc", region=""):
    token = csrf_from(client, "/products/new")
    client.post("/products/new", data={
        "csrf_token": token, "title": title, "description": "설명",
        "price": str(price), "category": category, "region": region,
    }, follow_redirects=True)


def _balance(app, username):
    conn = sqlite3.connect(app.config["DATABASE"])
    v = conn.execute("SELECT balance FROM users WHERE username=?", (username,)).fetchone()[0]
    conn.close()
    return v


def _pstatus(app, pid):
    conn = sqlite3.connect(app.config["DATABASE"])
    v = conn.execute("SELECT status FROM products WHERE id=?", (pid,)).fetchone()[0]
    conn.close()
    return v


def _order_id(app, product_id):
    conn = sqlite3.connect(app.config["DATABASE"])
    row = conn.execute("SELECT id FROM orders WHERE product_id=? ORDER BY id DESC LIMIT 1",
                       (product_id,)).fetchone()
    conn.close()
    return row[0] if row else None


def test_escrow_hold_confirm_and_review(app):
    seller = app.test_client()
    register(seller, "esell"); login(seller, "esell")
    _create_priced_product(seller, 134, "싼물건")      # id 1
    buyer = app.test_client()
    register(buyer, "ebuy"); login(buyer, "ebuy")
    buyer.post("/wallet/topup", data={
        "csrf_token": csrf_from(buyer, "/wallet/"), "amount": "10000"}, follow_redirects=True)

    # 결제 -> 보류: 1만원 넣어도 딱 134원만, 판매자에겐 아직 정산 안 됨
    r = buyer.post("/wallet/buy/1", data={"csrf_token": csrf_from(buyer, "/wallet/")},
                   follow_redirects=True)
    assert "보류" in r.get_data(as_text=True)
    assert _balance(app, "ebuy") == 10000 - 134
    assert _balance(app, "esell") == 0
    assert _pstatus(app, 1) == "sold"
    oid = _order_id(app, 1)

    # 구매 확정 -> 판매자 정산
    r = buyer.post(f"/wallet/orders/{oid}/confirm",
                   data={"csrf_token": csrf_from(buyer, "/wallet/")}, follow_redirects=True)
    assert "확정" in r.get_data(as_text=True)
    assert _balance(app, "esell") == 134

    # 후기 작성 -> 판매자 평판 반영
    r = buyer.post(f"/wallet/orders/{oid}/review",
                   data={"csrf_token": csrf_from(buyer, "/wallet/"),
                         "rating": "5", "comment": "좋아요"}, follow_redirects=True)
    assert "후기" in r.get_data(as_text=True)
    conn = sqlite3.connect(app.config["DATABASE"])
    sid = conn.execute("SELECT id FROM users WHERE username='esell'").fetchone()[0]
    conn.close()
    assert "평판" in buyer.get(f"/auth/user/{sid}").get_data(as_text=True)


def test_escrow_cancel_refunds(app):
    seller = app.test_client()
    register(seller, "csell"); login(seller, "csell")
    _create_priced_product(seller, 300, "의자")        # id 1
    buyer = app.test_client()
    register(buyer, "cbuy"); login(buyer, "cbuy")
    buyer.post("/wallet/topup", data={
        "csrf_token": csrf_from(buyer, "/wallet/"), "amount": "1000"}, follow_redirects=True)

    buyer.post("/wallet/buy/1", data={"csrf_token": csrf_from(buyer, "/wallet/")},
               follow_redirects=True)
    assert _balance(app, "cbuy") == 700
    assert _pstatus(app, 1) == "sold"
    oid = _order_id(app, 1)

    # 취소 -> 전액 환불, 상품 다시 판매중
    r = buyer.post(f"/wallet/orders/{oid}/cancel",
                   data={"csrf_token": csrf_from(buyer, "/wallet/")}, follow_redirects=True)
    assert "환불" in r.get_data(as_text=True)
    assert _balance(app, "cbuy") == 1000
    assert _pstatus(app, 1) == "active"


def test_purchase_insufficient_goes_to_topup(app):
    seller = app.test_client()
    register(seller, "seller10"); login(seller, "seller10")
    _create_priced_product(seller, 5000, "비싼물건")   # id 1

    buyer = app.test_client()
    register(buyer, "buyer10"); login(buyer, "buyer10")   # 잔액 0

    r = buyer.post("/wallet/buy/1", data={
        "csrf_token": csrf_from(buyer, "/wallet/")}, follow_redirects=False)
    assert r.status_code == 302
    assert "/wallet" in r.headers["Location"]      # 충전 화면으로 이동
    assert _balance(app, "buyer10") == 0           # 잔액 변화 없음
    assert _pstatus(app, 1) == "active"            # 상품 그대로


def test_cannot_buy_own_product(app):
    seller = app.test_client()
    register(seller, "owner9"); login(seller, "owner9")
    _create_priced_product(seller, 100, "내물건")     # id 1
    seller.post("/wallet/topup", data={
        "csrf_token": csrf_from(seller, "/wallet/"), "amount": "1000"},
        follow_redirects=True)
    r = seller.post("/wallet/buy/1", data={
        "csrf_token": csrf_from(seller, "/wallet/")}, follow_redirects=True)
    assert "본인 상품" in r.get_data(as_text=True)
    assert _pstatus(app, 1) == "active"


def test_cannot_buy_already_reserved_product(app):
    seller = app.test_client()
    register(seller, "seller11"); login(seller, "seller11")
    _create_priced_product(seller, 100, "한정판")     # id 1

    b1 = app.test_client()
    register(b1, "buyerA"); login(b1, "buyerA")
    b1.post("/wallet/topup", data={
        "csrf_token": csrf_from(b1, "/wallet/"), "amount": "1000"}, follow_redirects=True)
    b2 = app.test_client()
    register(b2, "buyerB"); login(b2, "buyerB")
    b2.post("/wallet/topup", data={
        "csrf_token": csrf_from(b2, "/wallet/"), "amount": "1000"}, follow_redirects=True)

    b1.post("/wallet/buy/1", data={"csrf_token": csrf_from(b1, "/wallet/")},
            follow_redirects=True)
    r = b2.post("/wallet/buy/1", data={"csrf_token": csrf_from(b2, "/wallet/")},
                follow_redirects=True)
    assert "이미 판매" in r.get_data(as_text=True)
    assert _balance(app, "buyerB") == 1000     # 두 번째 구매자는 돈이 안 빠짐
    assert _balance(app, "seller11") == 0      # 확정 전이라 판매자도 0


def test_concurrent_hold_single_winner(app):
    """세 명이 동시에 같은 상품을 결제해도 한 명만 대금 보류에 성공한다(중복 판매 방지)."""
    import threading
    from app.blueprints.payments import _do_hold
    from app.db import get_write_connection

    with app.app_context():
        db = get_write_connection()
        db.execute("INSERT INTO users (username,password_hash,display_name,balance)"
                   " VALUES ('cpsel','x','cpsel',0)")
        sid = db.execute("SELECT id FROM users WHERE username='cpsel'").fetchone()[0]
        db.execute("INSERT INTO products (seller_id,title,description,price,status)"
                   " VALUES (?,?,?,?, 'active')", (sid, "race", "d", 100))
        pid = db.execute("SELECT id FROM products WHERE title='race'").fetchone()[0]
        buyers = []
        for name in ("cpb1", "cpb2", "cpb3"):
            db.execute("INSERT INTO users (username,password_hash,display_name,balance)"
                       " VALUES (?,?,?,1000)", (name, "x", name))
            buyers.append(
                db.execute("SELECT id FROM users WHERE username=?", (name,)).fetchone()[0])
        db.close()

    results = []
    lock = threading.Lock()

    def worker(bid):
        with app.app_context():
            status, _, _ = _do_hold(bid, pid)
        with lock:
            results.append(status)

    threads = [threading.Thread(target=worker, args=(b,)) for b in buyers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with app.app_context():
        db = get_write_connection()
        st = db.execute("SELECT status FROM products WHERE id=?", (pid,)).fetchone()[0]
        sbal = db.execute("SELECT balance FROM users WHERE id=?", (sid,)).fetchone()[0]
        held = db.execute("SELECT COUNT(*) FROM orders WHERE product_id=? AND status='held'",
                          (pid,)).fetchone()[0]
        transfers = db.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        db.close()

    assert results.count("ok") == 1     # 정확히 한 명만 성공
    assert st == "sold"                 # 거래중
    assert held == 1                    # 보류 주문 1건뿐
    assert sbal == 0                    # 확정 전이라 정산 없음
    assert transfers == 0               # 정산(원장)도 아직 없음


# --- 찜(관심상품) ---------------------------------------------------------
def test_favorite_toggle(app):
    seller = app.test_client()
    register(seller, "fsell"); login(seller, "fsell")
    _create_priced_product(seller, 100, "찜상품")     # id 1
    buyer = app.test_client()
    register(buyer, "fbuy"); login(buyer, "fbuy")

    buyer.post("/products/1/favorite", data={"csrf_token": csrf_from(buyer, "/wallet/")},
               follow_redirects=True)
    assert "찜상품" in buyer.get("/products/favorites").get_data(as_text=True)

    buyer.post("/products/1/favorite", data={"csrf_token": csrf_from(buyer, "/wallet/")},
               follow_redirects=True)
    assert "찜상품" not in buyer.get("/products/favorites").get_data(as_text=True)

    # 본인 상품은 찜 불가
    r = seller.post("/products/1/favorite", data={"csrf_token": csrf_from(seller, "/wallet/")},
                    follow_redirects=True)
    assert "본인 상품" in r.get_data(as_text=True)


# --- 카테고리 필터 + 정렬 -------------------------------------------------
def test_category_filter_and_sort(app):
    seller = app.test_client()
    register(seller, "catsel"); login(seller, "catsel")
    _create_priced_product(seller, 500000, "노트북", category="digital")
    _create_priced_product(seller, 20000, "청바지", category="clothing")
    _create_priced_product(seller, 80000, "책상", category="furniture")

    # 카테고리 필터
    r = seller.get("/products/?category=clothing").get_data(as_text=True)
    assert "청바지" in r and "노트북" not in r
    # 잘못된 카테고리는 무시(전체 노출)
    r2 = seller.get("/products/?category=hacker").get_data(as_text=True)
    assert "노트북" in r2 and "청바지" in r2
    # 가격 낮은순 정렬: 청바지(2만) 가 노트북(50만) 보다 앞
    r3 = seller.get("/products/?sort=price_asc").get_data(as_text=True)
    assert r3.index("청바지") < r3.index("노트북")


# --- 보류(거래중) 상태 표시 + 구매내역 -----------------------------------
def test_held_product_shows_in_progress_not_completed(app):
    seller = app.test_client()
    register(seller, "hsell"); login(seller, "hsell")
    _create_priced_product(seller, 100, "보류상품")     # id 1
    buyer = app.test_client()
    register(buyer, "hbuy"); login(buyer, "hbuy")
    buyer.post("/wallet/topup", data={
        "csrf_token": csrf_from(buyer, "/wallet/"), "amount": "1000"}, follow_redirects=True)
    # 찜 + 결제(보류)
    buyer.post("/products/1/favorite", data={"csrf_token": csrf_from(buyer, "/wallet/")},
               follow_redirects=True)
    buyer.post("/wallet/buy/1", data={"csrf_token": csrf_from(buyer, "/wallet/")},
               follow_redirects=True)

    # 관심목록: '거래중'이어야 하고 '거래완료'가 아니어야 한다
    fav = buyer.get("/products/favorites").get_data(as_text=True)
    assert "거래중" in fav and "거래완료" not in fav
    # 메인: 보류 상품이 사라지지 않고 '거래중'으로 보인다
    home = buyer.get("/").get_data(as_text=True)
    assert "보류상품" in home and "거래중" in home
    # 목록에서도 보인다
    lst = buyer.get("/products/").get_data(as_text=True)
    assert "보류상품" in lst


def test_my_orders_page_confirm(app):
    seller = app.test_client()
    register(seller, "osell"); login(seller, "osell")
    _create_priced_product(seller, 500, "주문상품")     # id 1
    buyer = app.test_client()
    register(buyer, "obuy"); login(buyer, "obuy")
    buyer.post("/wallet/topup", data={
        "csrf_token": csrf_from(buyer, "/wallet/"), "amount": "1000"}, follow_redirects=True)
    buyer.post("/wallet/buy/1", data={"csrf_token": csrf_from(buyer, "/wallet/")},
               follow_redirects=True)

    # 구매내역에 보류 주문이 보인다
    orders = buyer.get("/wallet/orders").get_data(as_text=True)
    assert "주문상품" in orders and "결제 보류중" in orders

    # 구매내역에서 바로 구매 확정 -> 판매자 정산
    oid = _order_id(app, 1)
    buyer.post(f"/wallet/orders/{oid}/confirm",
               data={"csrf_token": csrf_from(buyer, "/wallet/")}, follow_redirects=True)
    assert _balance(app, "osell") == 500


# --- 상품별 대화 분리 -----------------------------------------------------
def test_chat_is_separated_per_product(app):
    seller = app.test_client()
    register(seller, "chsell"); login(seller, "chsell")   # id 2
    _create_priced_product(seller, 100, "상품일")          # id 1
    _create_priced_product(seller, 200, "상품이")          # id 2
    buyer = app.test_client()
    register(buyer, "chbuy"); login(buyer, "chbuy")        # id 3

    # 같은 판매자(2)의 서로 다른 상품에 각각 문의
    buyer.post("/chat/1/2", data={"csrf_token": csrf_from(buyer, "/wallet/"),
                                  "body": "상품일 문의"}, follow_redirects=True)
    buyer.post("/chat/2/2", data={"csrf_token": csrf_from(buyer, "/wallet/"),
                                  "body": "상품이 문의"}, follow_redirects=True)

    # 상품1 대화방에는 상품1 메시지만, 상품2 메시지는 섞이지 않아야 한다
    t1 = buyer.get("/chat/1/2").get_data(as_text=True)
    assert "상품일 문의" in t1 and "상품이 문의" not in t1
    t2 = buyer.get("/chat/2/2").get_data(as_text=True)
    assert "상품이 문의" in t2 and "상품일 문의" not in t2

    # 목록에는 두 개의 상품별 대화가 따로 보인다
    inbox = buyer.get("/chat/").get_data(as_text=True)
    assert "상품일" in inbox and "상품이" in inbox


def test_chat_third_party_cannot_read(app):
    seller = app.test_client()
    register(seller, "idsell"); login(seller, "idsell")    # id 2
    _create_priced_product(seller, 100, "비밀상품")         # id 1
    buyer = app.test_client()
    register(buyer, "idbuy"); login(buyer, "idbuy")        # id 3
    buyer.post("/chat/1/2", data={"csrf_token": csrf_from(buyer, "/wallet/"),
                                  "body": "비밀문의"}, follow_redirects=True)

    third = app.test_client()
    register(third, "idthird"); login(third, "idthird")    # id 4
    # 제3자가 구매자의 대화(상품1/구매자3)를 열람 시도 -> 403
    assert third.get("/chat/1/3").status_code == 403
    # 제3자가 판매자와 새 대화를 열어도, 남의 대화 내용은 안 보인다
    r = third.get("/chat/1/2").get_data(as_text=True)
    assert "비밀문의" not in r


# --- 금액 파서 엄격성(단위 테스트) ----------------------------------------
def test_amount_parser_strictness():
    from app.validators import validate_amount

    assert validate_amount("1000") == 1000
    assert validate_amount("1,000") == 1000
    for bad in ["1,2,3", "１２３", "-1", "1.5", "0", "abc", "1e9", "  "]:
        with pytest.raises(ValueError):
            validate_amount(bad)
