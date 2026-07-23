"""관리자 콘솔.

플랫폼의 모든 요소(사용자, 상품, 신고, 송금 내역)를 조회/관리한다.
모든 라우트에 admin_required 를 걸어 일반 사용자의 접근을 차단한다.
상태 변경은 모두 POST + CSRF 로만 가능하다.
"""
from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ..db import get_db
from ..security import admin_required, current_user

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def dashboard():
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "blocked_users": db.execute(
            "SELECT COUNT(*) c FROM users WHERE status='blocked'").fetchone()["c"],
        "products": db.execute("SELECT COUNT(*) c FROM products").fetchone()["c"],
        "blocked_products": db.execute(
            "SELECT COUNT(*) c FROM products WHERE status='blocked'").fetchone()["c"],
        "open_reports": db.execute(
            "SELECT COUNT(*) c FROM reports WHERE status='open'").fetchone()["c"],
        "transfers": db.execute("SELECT COUNT(*) c FROM transfers").fetchone()["c"],
    }
    return render_template("admin/dashboard.html", stats=stats)


@bp.route("/users")
@admin_required
def users():
    db = get_db()
    rows = db.execute(
        """SELECT id, username, display_name, role, status, balance, created_at
           FROM users ORDER BY created_at DESC"""
    ).fetchall()
    return render_template("admin/users.html", users=rows)


@bp.route("/users/<int:user_id>/block", methods=("POST",))
@admin_required
def block_user(user_id):
    db = get_db()
    target = db.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    if target["role"] == "admin":
        flash("관리자 계정은 차단할 수 없습니다.")
        return redirect(url_for("admin.users"))
    db.execute("UPDATE users SET status = 'blocked' WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자를 차단했습니다.")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/unblock", methods=("POST",))
@admin_required
def unblock_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자 차단을 해제했습니다.")
    return redirect(url_for("admin.users"))


@bp.route("/products")
@admin_required
def products():
    db = get_db()
    rows = db.execute(
        """SELECT p.id, p.title, p.price, p.status, u.display_name AS seller_name
           FROM products p JOIN users u ON u.id = p.seller_id
           ORDER BY p.created_at DESC"""
    ).fetchall()
    return render_template("admin/products.html", products=rows)


@bp.route("/products/<int:product_id>/block", methods=("POST",))
@admin_required
def block_product(product_id):
    db = get_db()
    if db.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone() is None:
        abort(404)
    db.execute("UPDATE products SET status = 'blocked' WHERE id = ?", (product_id,))
    db.commit()
    flash("상품을 차단했습니다.")
    return redirect(url_for("admin.products"))


@bp.route("/products/<int:product_id>/unblock", methods=("POST",))
@admin_required
def unblock_product(product_id):
    db = get_db()
    db.execute("UPDATE products SET status = 'active' WHERE id = ?", (product_id,))
    db.commit()
    flash("상품 차단을 해제했습니다.")
    return redirect(url_for("admin.products"))


@bp.route("/reports")
@admin_required
def reports():
    db = get_db()
    rows = db.execute(
        """SELECT r.*, u.display_name AS reporter_name
           FROM reports r JOIN users u ON u.id = r.reporter_id
           ORDER BY (r.status = 'open') DESC, r.created_at DESC"""
    ).fetchall()
    return render_template("admin/reports.html", reports=rows)


@bp.route("/reports/<int:report_id>/resolve", methods=("POST",))
@admin_required
def resolve_report(report_id):
    decision = request.form.get("decision")
    if decision not in ("resolved", "dismissed"):
        abort(400)
    db = get_db()
    if db.execute("SELECT id FROM reports WHERE id = ?", (report_id,)).fetchone() is None:
        abort(404)
    db.execute("UPDATE reports SET status = ? WHERE id = ?", (decision, report_id))
    db.commit()
    flash("신고를 처리했습니다.")
    return redirect(url_for("admin.reports"))


@bp.route("/transfers")
@admin_required
def transfers():
    db = get_db()
    rows = db.execute(
        """SELECT t.*, s.display_name AS sender_name, r.display_name AS receiver_name
           FROM transfers t
           JOIN users s ON s.id = t.sender_id
           JOIN users r ON r.id = t.receiver_id
           ORDER BY t.created_at DESC LIMIT 200"""
    ).fetchall()
    return render_template("admin/transfers.html", transfers=rows)
