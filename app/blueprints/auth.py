"""회원가입 / 로그인 / 로그아웃 / 내 정보."""
from urllib.parse import urlparse

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from ..db import get_db
from ..security import (
    current_user,
    login_required,
    login_user,
    logout_user,
    record_login_attempt,
    is_login_blocked,
    clear_login_attempts,
    rate_limit,
)
from ..validators import validate_username, validate_password, validate_text

bp = Blueprint("auth", __name__, url_prefix="/auth")

# 존재하지 않는 계정으로 로그인할 때도 진짜 해시 검증과 동일한 시간을 쓰기 위한
# 더미 해시. 무작위 문자열로 미리 생성해 둔다(계정 존재 여부를 시간차로 노출하지 않음).
import secrets as _secrets  # noqa: E402
_DUMMY_HASH = generate_password_hash(_secrets.token_hex(16))


def _is_safe_next(target):
    """오픈 리다이렉트 방지: 같은 사이트 내부 경로만 허용."""
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc and target.startswith("/")


@bp.route("/register", methods=("GET", "POST"))
def register():
    if current_user():
        return redirect(url_for("main.index"))

    if request.method == "POST":
        # IP 기준 가입 남용 방지
        if rate_limit(f"register:{request.remote_addr}", max_calls=10, per_seconds=3600):
            flash("가입 시도가 너무 많습니다. 잠시 후 다시 시도하세요.")
            return render_template("auth/register.html"), 429

        try:
            username = validate_username(request.form.get("username"))
            password = validate_password(request.form.get("password"))
            display_name = validate_text(request.form.get("display_name"), "display_name")
        except ValueError as exc:
            flash(str(exc))
            return render_template("auth/register.html",
                                   form=request.form), 400

        db = get_db()
        exists = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if exists:
            flash("이미 사용 중인 아이디입니다.")
            return render_template("auth/register.html", form=request.form), 409

        db.execute(
            """INSERT INTO users (username, password_hash, display_name)
               VALUES (?, ?, ?)""",
            (username, generate_password_hash(password), display_name),
        )
        db.commit()
        flash("가입이 완료되었습니다. 로그인해 주세요.")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if current_user():
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # 계정명 + IP 두 축으로 레이트리밋을 건다.
        ip = request.remote_addr or "unknown"
        if is_login_blocked(username) or is_login_blocked(f"ip:{ip}"):
            flash("로그인 시도가 너무 많습니다. 15분 후 다시 시도하세요.")
            return render_template("auth/login.html"), 429

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # 사용자 존재 여부와 무관하게 비밀번호 해시 검증을 수행해
        # 응답 시간 차이로 계정 존재를 추측하지 못하게 한다(타이밍 방어).
        stored_hash = user["password_hash"] if user else _DUMMY_HASH
        password_ok = check_password_hash(stored_hash, password)

        if user and password_ok and user["status"] == "active":
            record_login_attempt(username, success=True)
            clear_login_attempts(username)
            clear_login_attempts(f"ip:{ip}")
            login_user(user["id"])
            flash("로그인되었습니다.")
            nxt = request.args.get("next")
            if _is_safe_next(nxt):
                return redirect(nxt)
            return redirect(url_for("main.index"))

        # 실패 처리 (차단 계정도 동일 메시지로 정보 노출 최소화)
        record_login_attempt(username, success=False)
        record_login_attempt(f"ip:{ip}", success=False)
        if user and user["status"] == "blocked":
            flash("차단된 계정입니다. 관리자에게 문의하세요.")
        else:
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return render_template("auth/login.html"), 401

    return render_template("auth/login.html")


@bp.route("/logout", methods=("POST",))
@login_required
def logout():
    logout_user()
    flash("로그아웃되었습니다.")
    return redirect(url_for("main.index"))


@bp.route("/me", methods=("GET", "POST"))
@login_required
def me():
    user = current_user()
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "profile":
            try:
                display_name = validate_text(request.form.get("display_name"), "display_name")
                bio = validate_text(request.form.get("bio"), "bio", allow_empty=True)
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for("auth.me"))
            db.execute(
                "UPDATE users SET display_name = ?, bio = ? WHERE id = ?",
                (display_name, bio, user["id"]),
            )
            db.commit()
            flash("프로필을 수정했습니다.")

        elif action == "password":
            current_pw = request.form.get("current_password") or ""
            if not check_password_hash(user["password_hash"], current_pw):
                flash("현재 비밀번호가 올바르지 않습니다.")
                return redirect(url_for("auth.me"))
            try:
                new_pw = validate_password(request.form.get("new_password"))
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for("auth.me"))
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_pw), user["id"]),
            )
            db.commit()
            flash("비밀번호를 변경했습니다.")

        return redirect(url_for("auth.me"))

    return render_template("auth/me.html", user=user)


@bp.route("/user/<int:user_id>")
def profile(user_id):
    """공개 프로필. 활성 사용자만, 민감정보(잔액/해시)는 노출하지 않는다."""
    db = get_db()
    user = db.execute(
        """SELECT id, username, display_name, bio, created_at, status
           FROM users WHERE id = ?""",
        (user_id,),
    ).fetchone()
    if user is None or user["status"] != "active":
        flash("존재하지 않거나 차단된 사용자입니다.")
        return redirect(url_for("main.index"))

    products = db.execute(
        """SELECT id, title, price, image_path, status FROM products
           WHERE seller_id = ? AND status != 'blocked'
           ORDER BY created_at DESC""",
        (user_id,),
    ).fetchall()
    return render_template("auth/profile.html", profile=user, products=products)
