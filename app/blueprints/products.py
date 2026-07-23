"""상품 등록 / 조회 / 수정 / 삭제 / 검색 / 이미지."""
import os
import secrets

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from ..db import get_db
from ..security import current_user, login_required
from ..validators import validate_text, validate_price

bp = Blueprint("products", __name__, url_prefix="/products")

# 허용 이미지 형식: 확장자와 매직바이트(파일 시그니처)를 함께 검사한다.
ALLOWED_IMAGE = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "jpeg": b"\xff\xd8\xff",
    "gif": b"GIF8",
    "webp": None,  # 'RIFF'....'WEBP' 은 아래에서 별도 확인
}


def _sniff_ok(ext, head):
    """확장자에 맞는 시그니처인지 확인. 위장 파일 업로드 차단."""
    ext = ext.lower()
    if ext not in ALLOWED_IMAGE:
        return False
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    sig = ALLOWED_IMAGE[ext]
    return head.startswith(sig)


def _save_image(file_storage):
    """업로드 이미지를 검증 후 무작위 파일명으로 저장. 저장된 파일명을 반환.

    - 확장자 화이트리스트
    - 매직바이트 확인 (Content-Type 헤더는 신뢰하지 않음)
    - 무작위 파일명 사용 (사용자 입력 파일명은 저장 경로에 절대 반영하지 않음 -> 경로순회 차단)
    """
    if not file_storage or not file_storage.filename:
        return None

    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_IMAGE:
        raise ValueError("허용되지 않는 이미지 형식입니다(png, jpg, gif, webp).")

    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if not _sniff_ok(ext, head):
        raise ValueError("이미지 파일이 손상되었거나 형식이 확장자와 일치하지 않습니다.")

    # 확장자는 jpg 로 정규화
    if ext == "jpeg":
        ext = "jpg"
    filename = f"{secrets.token_hex(16)}.{ext}"
    dest = os.path.join(current_app.config["UPLOAD_DIR"], filename)
    file_storage.save(dest)
    return filename


@bp.route("/")
def listing():
    """상품 목록 + 검색.

    검색어는 LIKE 파라미터 바인딩으로 처리한다(SQL Injection 방지).
    """
    q = (request.args.get("q") or "").strip()
    db = get_db()

    if q:
        # LIKE 와일드카드/이스케이프 문자를 사용자 입력에서 무력화
        safe = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{safe}%"
        rows = db.execute(
            """
            SELECT p.id, p.title, p.price, p.image_path, p.created_at,
                   u.display_name AS seller_name
            FROM products p JOIN users u ON u.id = p.seller_id
            WHERE p.status = 'active' AND u.status = 'active'
              AND (p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\')
            ORDER BY p.created_at DESC
            LIMIT 100
            """,
            (like, like),
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT p.id, p.title, p.price, p.image_path, p.created_at,
                   u.display_name AS seller_name
            FROM products p JOIN users u ON u.id = p.seller_id
            WHERE p.status = 'active' AND u.status = 'active'
            ORDER BY p.created_at DESC
            LIMIT 100
            """
        ).fetchall()

    return render_template("products/list.html", products=rows, q=q)


@bp.route("/<int:product_id>")
def detail(product_id):
    db = get_db()
    product = db.execute(
        """
        SELECT p.*, u.display_name AS seller_name, u.status AS seller_status
        FROM products p JOIN users u ON u.id = p.seller_id
        WHERE p.id = ?
        """,
        (product_id,),
    ).fetchone()
    if product is None:
        abort(404)

    user = current_user()
    is_owner = user is not None and user["id"] == product["seller_id"]
    is_admin = user is not None and user["role"] == "admin"

    # 차단/삭제된 상품이나 차단된 판매자의 상품은 소유자/관리자만 볼 수 있다.
    if (product["status"] == "blocked" or product["seller_status"] != "active") \
            and not (is_owner or is_admin):
        abort(404)

    return render_template("products/detail.html", product=product,
                           is_owner=is_owner, is_admin=is_admin)


@bp.route("/new", methods=("GET", "POST"))
@login_required
def create():
    if request.method == "POST":
        try:
            title = validate_text(request.form.get("title"), "product_title")
            description = validate_text(request.form.get("description"), "product_description")
            price = validate_price(request.form.get("price"))
            image_name = _save_image(request.files.get("image"))
        except ValueError as exc:
            flash(str(exc))
            return render_template("products/form.html", form=request.form), 400

        db = get_db()
        cur = db.execute(
            """INSERT INTO products (seller_id, title, description, price, image_path)
               VALUES (?, ?, ?, ?, ?)""",
            (current_user()["id"], title, description, price, image_name),
        )
        db.commit()
        flash("상품을 등록했습니다.")
        return redirect(url_for("products.detail", product_id=cur.lastrowid))

    return render_template("products/form.html")


@bp.route("/<int:product_id>/edit", methods=("GET", "POST"))
@login_required
def edit(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    # 소유권 확인(IDOR 방지): 본인 상품만 수정 가능
    if product["seller_id"] != current_user()["id"]:
        abort(403)

    if request.method == "POST":
        try:
            title = validate_text(request.form.get("title"), "product_title")
            description = validate_text(request.form.get("description"), "product_description")
            price = validate_price(request.form.get("price"))
            status = request.form.get("status", "active")
            if status not in ("active", "sold"):
                raise ValueError("잘못된 상태값입니다.")
            new_image = _save_image(request.files.get("image"))
        except ValueError as exc:
            flash(str(exc))
            return render_template("products/form.html", form=request.form,
                                   product=product, editing=True), 400

        image_name = new_image if new_image else product["image_path"]
        db.execute(
            """UPDATE products SET title=?, description=?, price=?, status=?, image_path=?
               WHERE id = ? AND seller_id = ?""",
            (title, description, price, status, image_name,
             product_id, current_user()["id"]),
        )
        db.commit()
        # 이미지를 교체했다면 이전 파일 삭제
        if new_image and product["image_path"]:
            _remove_image(product["image_path"])
        flash("상품을 수정했습니다.")
        return redirect(url_for("products.detail", product_id=product_id))

    return render_template("products/form.html", product=product, editing=True)


@bp.route("/<int:product_id>/delete", methods=("POST",))
@login_required
def delete(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    user = current_user()
    # 소유자 또는 관리자만 삭제 가능
    if product["seller_id"] != user["id"] and user["role"] != "admin":
        abort(403)

    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db.commit()
    if product["image_path"]:
        _remove_image(product["image_path"])
    flash("상품을 삭제했습니다.")
    return redirect(url_for("main.index"))


@bp.route("/image/<path:filename>")
def image(filename):
    """업로드 이미지를 안전하게 서빙.

    send_from_directory 는 지정 폴더를 벗어나는 경로(../ 등)를 자동 차단한다.
    파일명 자체도 우리가 생성한 무작위 hex 라 예측/순회가 불가능하다.
    """
    return send_from_directory(current_app.config["UPLOAD_DIR"], filename)


def _remove_image(filename):
    try:
        path = os.path.join(current_app.config["UPLOAD_DIR"], filename)
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass
