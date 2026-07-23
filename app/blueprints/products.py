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
from ..security import current_user, login_required, rate_limit
from ..validators import (
    validate_text, validate_price, validate_category, validate_region,
)
from ..constants import SORTS, DEFAULT_SORT

bp = Blueprint("products", __name__, url_prefix="/products")


def reputation(db, user_id):
    """사용자의 평판(받은 후기 평균 별점 + 개수)."""
    row = db.execute(
        "SELECT COUNT(*) AS c, COALESCE(AVG(rating), 0) AS a FROM reviews WHERE target_id = ?",
        (user_id,),
    ).fetchone()
    return {"count": row["c"], "avg": round(row["a"], 1)}

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


PAGE_SIZE = 12          # 한 페이지 상품 수
SEARCH_MAX_LEN = 100    # 검색어 길이 상한


@bp.route("/")
def listing():
    """상품 목록 + 검색 + 페이지네이션.

    검색어는 LIKE 파라미터 바인딩으로 처리한다(SQL Injection 방지).
    """
    q = (request.args.get("q") or "").strip()[:SEARCH_MAX_LEN]
    category = (request.args.get("category") or "").strip()
    region = (request.args.get("region") or "").strip()[:30]
    sort = request.args.get("sort", DEFAULT_SORT)
    if sort not in SORTS:
        sort = DEFAULT_SORT

    # 페이지 번호 파싱(1 미만/비정상 값은 1로 보정)
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    if page < 1:
        page = 1
    offset = (page - 1) * PAGE_SIZE

    db = get_db()

    # 공통 WHERE 절과 파라미터를 조건에 따라 구성 (모두 파라미터 바인딩)
    # 판매중 + '거래중(결제 보류)' 상품을 보여 주고, 거래 완료 상품은 제외한다.
    where = ("u.status = 'active' AND (p.status = 'active' "
             "OR EXISTS (SELECT 1 FROM orders o "
             "WHERE o.product_id = p.id AND o.status = 'held'))")
    params = []
    if q:
        # LIKE 와일드카드/이스케이프 문자를 사용자 입력에서 무력화
        safe = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{safe}%"
        where += " AND (p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\')"
        params += [like, like]
    if category:
        # 정해진 카테고리 키만 허용
        from ..constants import CATEGORY_KEYS
        if category in CATEGORY_KEYS:
            where += " AND p.category = ?"
            params.append(category)
        else:
            category = ""
    if region:
        safe_r = region.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where += " AND p.region LIKE ? ESCAPE '\\'"
        params.append(f"%{safe_r}%")

    total = db.execute(
        f"SELECT COUNT(*) AS c FROM products p JOIN users u ON u.id = p.seller_id WHERE {where}",
        params,
    ).fetchone()["c"]

    # 정렬은 화이트리스트에서 가져온 고정 문자열만 사용(ORDER BY 인젝션 방지)
    order_by = SORTS[sort][1]
    rows = db.execute(
        f"""
        SELECT p.id, p.title, p.price, p.image_path, p.created_at, p.region, p.status,
               u.display_name AS seller_name,
               (SELECT COUNT(*) FROM favorites f WHERE f.product_id = p.id) AS fav_count,
               (SELECT o.status FROM orders o
                WHERE o.product_id = p.id AND o.status IN ('held', 'confirmed')
                ORDER BY o.id DESC LIMIT 1) AS order_status
        FROM products p JOIN users u ON u.id = p.seller_id
        WHERE {where}
        ORDER BY {order_by}
        LIMIT ? OFFSET ?
        """,
        params + [PAGE_SIZE, offset],
    ).fetchall()

    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return render_template(
        "products/list.html",
        products=rows, q=q, page=page, total_pages=total_pages, total=total,
        category=category, region=region, sort=sort,
    )


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

    # 찜 상태/개수
    fav_count = db.execute(
        "SELECT COUNT(*) AS c FROM favorites WHERE product_id = ?", (product_id,)
    ).fetchone()["c"]
    favorited = False
    if user is not None:
        favorited = db.execute(
            "SELECT 1 FROM favorites WHERE user_id = ? AND product_id = ?",
            (user["id"], product_id),
        ).fetchone() is not None

    # 이 상품의 진행 중/완료된 주문(에스크로) — 취소된 건 제외, 최신 1건
    order = db.execute(
        """SELECT * FROM orders WHERE product_id = ? AND status IN ('held', 'confirmed')
           ORDER BY id DESC LIMIT 1""",
        (product_id,),
    ).fetchone()

    my_review = None
    if order is not None and order["status"] == "confirmed" and user is not None \
            and user["id"] == order["buyer_id"]:
        my_review = db.execute(
            "SELECT id FROM reviews WHERE order_id = ? AND reviewer_id = ?",
            (order["id"], user["id"]),
        ).fetchone()

    seller_rep = reputation(db, product["seller_id"])

    return render_template("products/detail.html", product=product,
                           is_owner=is_owner, is_admin=is_admin,
                           fav_count=fav_count, favorited=favorited,
                           order=order, my_review=my_review, seller_rep=seller_rep)


@bp.route("/new", methods=("GET", "POST"))
@login_required
def create():
    if request.method == "POST":
        try:
            title = validate_text(request.form.get("title"), "product_title")
            description = validate_text(request.form.get("description"), "product_description")
            price = validate_price(request.form.get("price"))
            category = validate_category(request.form.get("category"))
            region = validate_region(request.form.get("region"))
            image_name = _save_image(request.files.get("image"))
        except ValueError as exc:
            flash(str(exc))
            return render_template("products/form.html", form=request.form), 400

        db = get_db()
        cur = db.execute(
            """INSERT INTO products (seller_id, title, description, price,
                                     category, region, image_path)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (current_user()["id"], title, description, price,
             category, region, image_name),
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
    # 관리자/자동 모더레이션으로 차단된 상품은 소유자가 수정해 되살릴 수 없다.
    # (status 폼 값으로 blocked -> active 우회 차단)
    if product["status"] == "blocked":
        flash("차단된 상품은 수정할 수 없습니다. 관리자에게 문의하세요.")
        return redirect(url_for("products.detail", product_id=product_id))

    if request.method == "POST":
        try:
            title = validate_text(request.form.get("title"), "product_title")
            description = validate_text(request.form.get("description"), "product_description")
            price = validate_price(request.form.get("price"))
            category = validate_category(request.form.get("category"))
            region = validate_region(request.form.get("region"))
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
            """UPDATE products SET title=?, description=?, price=?, category=?,
                                   region=?, status=?, image_path=?
               WHERE id = ? AND seller_id = ?""",
            (title, description, price, category, region, status, image_name,
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
    is_admin = user["role"] == "admin"
    # 소유자 또는 관리자만 삭제 가능
    if product["seller_id"] != user["id"] and not is_admin:
        abort(403)
    # 차단된 상품은 신고/조사 근거이므로 소유자가 임의로 지울 수 없다(관리자만 가능).
    if product["status"] == "blocked" and not is_admin:
        flash("차단된 상품은 삭제할 수 없습니다.")
        return redirect(url_for("products.detail", product_id=product_id))

    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    # reports.target_id 는 다형(user/product) 참조라 FK 가 없다.
    # 상품이 사라지면 그 상품을 향한 신고도 함께 정리해 관리자 큐가 오염되지 않게 한다.
    db.execute(
        "DELETE FROM reports WHERE target_type = 'product' AND target_id = ?",
        (product_id,),
    )
    db.commit()
    if product["image_path"]:
        _remove_image(product["image_path"])
    flash("상품을 삭제했습니다.")
    return redirect(url_for("main.index"))


@bp.route("/favorites")
@login_required
def favorites():
    """내 관심목록(찜한 상품)."""
    me = current_user()
    rows = get_db().execute(
        """
        SELECT p.id, p.title, p.price, p.image_path, p.status, p.region,
               u.display_name AS seller_name,
               (SELECT o.status FROM orders o
                WHERE o.product_id = p.id AND o.status IN ('held', 'confirmed')
                ORDER BY o.id DESC LIMIT 1) AS order_status
        FROM favorites f
        JOIN products p ON p.id = f.product_id
        JOIN users u ON u.id = p.seller_id
        WHERE f.user_id = ?
        ORDER BY f.created_at DESC
        """,
        (me["id"],),
    ).fetchall()
    return render_template("products/favorites.html", products=rows)


@bp.route("/<int:product_id>/favorite", methods=("POST",))
@login_required
def toggle_favorite(product_id):
    """찜 토글(있으면 해제, 없으면 추가)."""
    me = current_user()
    db = get_db()
    product = db.execute(
        "SELECT id, seller_id FROM products WHERE id = ?", (product_id,)
    ).fetchone()
    if product is None:
        abort(404)
    if product["seller_id"] == me["id"]:
        flash("본인 상품은 찜할 수 없습니다.")
        return redirect(url_for("products.detail", product_id=product_id))

    if rate_limit(f"fav:{me['id']}", max_calls=60, per_seconds=60):
        flash("요청이 너무 잦습니다. 잠시 후 다시 시도하세요.")
        return redirect(url_for("products.detail", product_id=product_id))

    exists = db.execute(
        "SELECT 1 FROM favorites WHERE user_id = ? AND product_id = ?",
        (me["id"], product_id),
    ).fetchone()
    if exists:
        db.execute("DELETE FROM favorites WHERE user_id = ? AND product_id = ?",
                   (me["id"], product_id))
        flash("찜을 해제했습니다.")
    else:
        db.execute("INSERT INTO favorites (user_id, product_id) VALUES (?, ?)",
                   (me["id"], product_id))
        flash("찜했습니다.")
    db.commit()
    return redirect(url_for("products.detail", product_id=product_id))


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
