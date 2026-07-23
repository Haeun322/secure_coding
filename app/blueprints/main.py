"""메인 페이지 / 대시보드."""
from flask import Blueprint, render_template

from ..db import get_db
from ..security import current_user

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    db = get_db()
    # 최근 등록된 활성 상품 몇 개를 보여 준다.
    products = db.execute(
        """
        SELECT p.id, p.title, p.price, p.image_path, p.created_at,
               u.display_name AS seller_name
        FROM products p
        JOIN users u ON u.id = p.seller_id
        WHERE p.status = 'active' AND u.status = 'active'
        ORDER BY p.created_at DESC
        LIMIT 12
        """
    ).fetchall()
    return render_template("index.html", products=products, user=current_user())
