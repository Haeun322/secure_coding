"""애플리케이션 팩토리.

create_app() 이 앱을 조립한다. 설정 로드 -> 폴더 준비 -> DB/보안 초기화 ->
블루프린트 등록 -> 관리자 부트스트랩 순서.
"""
import os

from flask import Flask, render_template

from .config import Config
from . import db
from .security import init_csrf, init_security_headers, current_user


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=False)

    cfg = Config()
    app.config.update(cfg.as_dict())
    if test_config:
        app.config.update(test_config)

    # 프록시 뒤에 있을 때만 X-Forwarded-* 를 신뢰해 실제 클라이언트 IP 를 복원한다.
    # (신뢰 홉 수를 명시하지 않으면 헤더 위조로 IP 를 속일 수 있어 기본은 비활성)
    hops = app.config.get("TRUST_PROXY_HOPS", 0)
    if hops and hops > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops)

    # instance 폴더(및 업로드 폴더) 준비
    os.makedirs(app.config["INSTANCE_DIR"], exist_ok=True)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    # DB teardown 등록
    db.init_app(app)

    # 보안: CSRF 자동 검증 + 응답 보안 헤더
    init_csrf(app)
    init_security_headers(app)

    # 블루프린트 등록
    from .blueprints import auth, products, chat, payments, reports, admin, main

    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(products.bp)
    app.register_blueprint(chat.bp)
    app.register_blueprint(payments.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(admin.bp)

    # 템플릿 전역: 현재 사용자 + 카테고리/정렬 상수
    from .constants import CATEGORIES, SORTS

    @app.context_processor
    def inject_globals():
        return {
            "current_user": current_user(),
            "CATEGORIES": CATEGORIES,
            "SORTS": SORTS,
        }

    # 에러 페이지
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                               message=getattr(e, "description", "접근 권한이 없습니다.")), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="페이지를 찾을 수 없습니다."), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", code=413,
                               message="업로드 용량이 너무 큽니다(최대 5MB)."), 413

    @app.errorhandler(429)
    def too_many(e):
        return render_template("error.html", code=429,
                               message="요청이 너무 많습니다. 잠시 후 다시 시도하세요."), 429

    # DB 초기화 + 관리자 부트스트랩을 앱 컨텍스트 안에서 수행
    with app.app_context():
        db.init_db()
        _bootstrap_admin(app)

    # CLI: flask init-db
    @app.cli.command("init-db")
    def init_db_command():
        db.init_db()
        print("데이터베이스를 초기화했습니다.")

    return app


def _bootstrap_admin(app):
    """ADMIN_USERNAME/ADMIN_PASSWORD 가 주어졌고, 그 계정이 아직 없으면 생성."""
    from werkzeug.security import generate_password_hash
    from .validators import validate_username, validate_password

    username = app.config.get("ADMIN_USERNAME")
    password = app.config.get("ADMIN_PASSWORD")
    if not username or not password:
        return

    try:
        username = validate_username(username)
        validate_password(password)
    except ValueError as exc:
        print(f"[warn] 관리자 계정 자동 생성 실패: {exc}")
        return

    conn = db.get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing:
        return

    conn.execute(
        """INSERT INTO users (username, password_hash, display_name, role)
           VALUES (?, ?, ?, 'admin')""",
        (username, generate_password_hash(password), username),
    )
    conn.commit()
    print(f"[info] 관리자 계정 '{username}' 을(를) 생성했습니다.")
