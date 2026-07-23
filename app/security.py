"""보안 공통 기능.

- CSRF 토큰 발급/검증
- 로그인/관리자 접근 제어 데코레이터
- 현재 사용자 조회 (세션 -> DB, 매 요청마다 상태 재확인)
- 로그인 브루트포스 레이트리밋
- 응답 보안 헤더

CSRF 는 외부 라이브러리 대신 세션 기반 토큰 + 상수시간 비교로 직접 구현했다.
동작 원리를 보고서에서 설명하기 위함이며, 검증 로직은 표준적인 방식과 동일하다.
"""
import functools
import hmac
import secrets
import time

from flask import (
    abort,
    current_app,
    flash,
    g,
    redirect,
    request,
    session,
    url_for,
)

from .db import get_db


# --- CSRF -----------------------------------------------------------------
def generate_csrf_token():
    """세션에 토큰이 없으면 새로 만들어 저장하고 반환."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf():
    """상태를 변경하는 요청(POST 등)에서 폼/헤더의 토큰을 검증.

    실패하면 403 으로 요청을 끊는다. hmac.compare_digest 로 상수시간 비교하여
    타이밍 공격을 방지한다.
    """
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    real = session.get("csrf_token", "")
    if not real or not sent or not hmac.compare_digest(sent, real):
        abort(403, description="CSRF 토큰이 올바르지 않습니다.")


def init_csrf(app):
    """상태 변경 메서드에 대해 자동으로 CSRF 검증을 걸고,
    템플릿에서 csrf_token() 을 쓸 수 있게 등록한다."""

    @app.before_request
    def _csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            validate_csrf()

    @app.context_processor
    def _inject_csrf():
        return {"csrf_token": generate_csrf_token}


# --- 현재 사용자 ----------------------------------------------------------
def current_user():
    """세션의 user_id 로 DB 에서 사용자를 다시 읽어 온다.

    매 요청마다 DB 를 확인하므로, 차단(blocked)된 사용자는 즉시 접근이 막힌다.
    (세션 쿠키만 믿지 않는다.)
    """
    if "user" in g:
        return g.user
    g.user = None
    uid = session.get("user_id")
    if uid is not None:
        row = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if row is None or row["status"] != "active":
            # 계정이 삭제되었거나 차단됨 -> 세션 무효화
            session.clear()
        else:
            g.user = row
    return g.user


def login_user(user_id):
    """세션 고정 공격 방지를 위해 로그인 시 세션을 새로 시작한다."""
    session.clear()
    session["user_id"] = user_id
    session.permanent = True
    # 새 CSRF 토큰 발급
    session["csrf_token"] = secrets.token_hex(32)


def logout_user():
    session.clear()


# --- 접근 제어 데코레이터 --------------------------------------------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("auth.login"))
        if user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


# --- 로그인 레이트리밋 ----------------------------------------------------
LOGIN_WINDOW_SECONDS = 15 * 60   # 15분
LOGIN_MAX_ATTEMPTS = 5           # 창(window) 내 실패 허용 횟수


def record_login_attempt(identifier, success):
    db = get_db()
    # 식별자는 공격자가 임의로 길게 보낼 수 있으므로 길이를 제한한다.
    identifier = (identifier or "")[:80]
    db.execute(
        "INSERT INTO login_attempts (identifier, success) VALUES (?, ?)",
        (identifier, 1 if success else 0),
    )
    # 테이블 무한 증가 방지: 가끔 창(window)을 벗어난 오래된 기록을 정리한다.
    if secrets.randbelow(10) == 0:
        db.execute(
            "DELETE FROM login_attempts WHERE attempt_at < datetime('now', ?)",
            (f"-{LOGIN_WINDOW_SECONDS} seconds",),
        )
    db.commit()


def is_login_blocked(identifier):
    """최근 창 안에서 실패가 임계치를 넘으면 True."""
    db = get_db()
    row = db.execute(
        """
        SELECT COUNT(*) AS c FROM login_attempts
        WHERE identifier = ?
          AND success = 0
          AND attempt_at >= datetime('now', ?)
        """,
        (identifier, f"-{LOGIN_WINDOW_SECONDS} seconds"),
    ).fetchone()
    return row["c"] >= LOGIN_MAX_ATTEMPTS


def clear_login_attempts(identifier):
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE identifier = ?", (identifier,))
    db.commit()


# --- 일반 요청 레이트리밋 (메모리 기반, 단일 프로세스 기준) ----------------
_rate_buckets = {}


def rate_limit(key, max_calls, per_seconds):
    """key 기준으로 per_seconds 동안 max_calls 를 넘으면 True(차단) 반환.

    간단한 슬라이딩 윈도우. 다중 워커 환경에서는 Redis 등으로 옮겨야 하지만,
    과제 범위(단일 프로세스)에서는 충분하다.
    """
    now = time.time()
    bucket = _rate_buckets.setdefault(key, [])
    # 오래된 기록 제거
    cutoff = now - per_seconds
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= max_calls:
        return True
    bucket.append(now)
    return False


# --- 보안 헤더 ------------------------------------------------------------
def init_security_headers(app):
    @app.after_request
    def _set_headers(resp):
        # 인라인 스크립트/스타일을 쓰지 않으므로 script/style-src 를 self 로 제한.
        # 인라인 style 속성과 인라인 이벤트 핸들러도 프로젝트에서 모두 제거해
        # 'unsafe-inline' 없이도 화면이 정상 동작한다(XSS 영향 최소화).
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "style-src 'self'; "
            "object-src 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"          # 클릭재킹 방지
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # HTTPS(운영)에서만 HSTS 를 보낸다. HTTP 로 켜면 개발이 불편해지므로 조건부.
        if app.config.get("SESSION_COOKIE_SECURE"):
            resp.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return resp
