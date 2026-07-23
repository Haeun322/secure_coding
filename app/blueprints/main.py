"""메인 페이지 / 대시보드."""
from flask import Blueprint, render_template

from ..db import get_db
from ..security import current_user

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    db = get_db()
    # 최근 상품: 판매중 + '거래중(결제 보류)' 상품을 함께 보여 준다.
    # 거래 완료된 상품은 제외한다.
    products = db.execute(
        """
        SELECT p.id, p.title, p.price, p.image_path, p.created_at, p.status, p.region,
               u.display_name AS seller_name,
               (SELECT o.status FROM orders o
                WHERE o.product_id = p.id AND o.status IN ('held', 'confirmed')
                ORDER BY o.id DESC LIMIT 1) AS order_status
        FROM products p
        JOIN users u ON u.id = p.seller_id
        WHERE u.status = 'active'
          AND (p.status = 'active'
               OR EXISTS (SELECT 1 FROM orders o
                          WHERE o.product_id = p.id AND o.status = 'held'))
        ORDER BY p.created_at DESC
        LIMIT 12
        """
    ).fetchall()
    return render_template("index.html", products=products, user=current_user())
