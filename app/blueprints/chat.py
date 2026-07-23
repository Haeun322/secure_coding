"""상품별 1:1 메시지.

대화는 '상품' 단위로 나뉜다. 같은 판매자라도 상품이 다르면 다른 대화방이다.
한 대화방은 (상품, 구매자) 조합으로 식별된다. 판매자는 상품의 소유자다.

접근 통제 원칙:
- 내가 판매자면 내 상품의 어떤 구매자와의 대화든 볼 수 있다.
- 내가 판매자가 아니면, 그 상품의 판매자와의 '내 대화'만 볼 수 있다.
- 그 외(제3자 대화 열람 시도)는 차단한다.
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
from ..security import current_user, login_required, rate_limit
from ..validators import validate_text

bp = Blueprint("chat", __name__, url_prefix="/chat")


@bp.route("/")
@login_required
def inbox():
    """내가 참여한 상품별 대화 목록 + 마지막 메시지."""
    me = current_user()["id"]
    db = get_db()
    # 각 메시지의 '구매자'는 판매자가 아닌 쪽. (상품, 구매자)로 묶어 마지막 메시지를 뽑는다.
    rows = db.execute(
        """
        SELECT c.product_id, c.buyer_id, c.seller_id,
               pr.title AS product_title, pr.status AS product_status,
               lm.body AS last_body, lm.created_at AS last_at,
               ou.id AS other_id, ou.display_name AS other_name
        FROM (
            SELECT m.product_id,
                   p.seller_id AS seller_id,
                   CASE WHEN m.sender_id = p.seller_id THEN m.receiver_id
                        ELSE m.sender_id END AS buyer_id,
                   MAX(m.id) AS last_id
            FROM messages m
            JOIN products p ON p.id = m.product_id
            WHERE m.product_id IS NOT NULL
              AND (m.sender_id = ? OR m.receiver_id = ?)
            GROUP BY m.product_id, buyer_id
        ) c
        JOIN messages lm ON lm.id = c.last_id
        JOIN products pr ON pr.id = c.product_id
        JOIN users ou ON ou.id = (CASE WHEN c.buyer_id = ? THEN c.seller_id ELSE c.buyer_id END)
        WHERE ou.status = 'active'
        ORDER BY c.last_id DESC
        """,
        (me, me, me),
    ).fetchall()
    return render_template("chat/inbox.html", conversations=rows, me_id=me)


@bp.route("/<int:product_id>/<int:peer_id>", methods=("GET", "POST"))
@login_required
def thread(product_id, peer_id):
    me = current_user()
    db = get_db()

    product = db.execute(
        "SELECT id, title, seller_id, status FROM products WHERE id = ?",
        (product_id,),
    ).fetchone()
    if product is None:
        abort(404)
    seller_id = product["seller_id"]

    # 역할 판별 + 당사자 검증
    if me["id"] == seller_id:
        buyer_id = peer_id              # 내가 판매자 -> 상대가 구매자
    elif peer_id == seller_id:
        buyer_id = me["id"]             # 내가 구매자 -> 상대가 판매자
    else:
        abort(403)                      # 이 상품 대화의 당사자가 아님
    if buyer_id == seller_id:
        flash("본인 상품에는 대화를 시작할 수 없습니다.")
        return redirect(url_for("products.detail", product_id=product_id))

    other_id = seller_id if me["id"] == buyer_id else buyer_id
    other = db.execute(
        "SELECT id, display_name, status FROM users WHERE id = ?", (other_id,)
    ).fetchone()
    if other is None or other["status"] != "active":
        abort(404)

    if request.method == "POST":
        if rate_limit(f"msg:{me['id']}", max_calls=20, per_seconds=60):
            flash("메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도하세요.")
            return redirect(url_for("chat.thread", product_id=product_id, peer_id=peer_id))
        try:
            body = validate_text(request.form.get("body"), "message_body")
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("chat.thread", product_id=product_id, peer_id=peer_id))
        db.execute(
            """INSERT INTO messages (product_id, sender_id, receiver_id, body)
               VALUES (?, ?, ?, ?)""",
            (product_id, me["id"], other_id, body),
        )
        db.commit()
        return redirect(url_for("chat.thread", product_id=product_id, peer_id=peer_id))

    # 이 상품에 대한, 나와 상대 사이의 메시지만 조회
    messages = db.execute(
        """
        SELECT * FROM messages
        WHERE product_id = ?
          AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ORDER BY created_at ASC, id ASC
        LIMIT 500
        """,
        (product_id, buyer_id, seller_id, seller_id, buyer_id),
    ).fetchall()
    return render_template("chat/thread.html", messages=messages, other=other,
                           me_id=me["id"], product=product)
