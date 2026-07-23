"""사용자 간 송금.

돈을 다루므로 가장 방어적으로 구현한다.
- 금액은 양의 정수(원)만 허용
- 비밀번호 재확인(재인증)
- 자기 자신에게 송금 불가 / 차단 사용자에게 송금 불가
- 잔액 확인과 차감/증가를 하나의 IMMEDIATE 트랜잭션 안에서 처리(경쟁 조건/이중지불 방지)
- DB 의 CHECK(balance >= 0) 제약이 마지막 안전망
"""
import sqlite3

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import check_password_hash

from ..db import get_db, get_write_connection
from ..security import current_user, login_required, rate_limit
from ..validators import validate_amount, validate_text, validate_rating

bp = Blueprint("payments", __name__, url_prefix="/wallet")

# 데모 충전으로 만들 수 있는 계정 잔액 총액 상한(원).
# 실서비스에서는 topup 을 실제 결제(PG) 승인 검증으로 대체해야 한다.
MAX_WALLET_BALANCE = 10_000_000


@bp.route("/")
@login_required
def wallet():
    me = current_user()
    db = get_db()
    transfers = db.execute(
        """
        SELECT t.*, s.display_name AS sender_name, r.display_name AS receiver_name
        FROM transfers t
        JOIN users s ON s.id = t.sender_id
        JOIN users r ON r.id = t.receiver_id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.created_at DESC
        LIMIT 100
        """,
        (me["id"], me["id"]),
    ).fetchall()
    return render_template("payments/wallet.html", user=me, transfers=transfers)


@bp.route("/orders")
@login_required
def my_orders():
    """내 구매내역. 보류(held) 건은 여기서 바로 구매 확정/취소할 수 있다."""
    me = current_user()
    db = get_db()
    orders = db.execute(
        """
        SELECT o.id, o.amount, o.status, o.created_at,
               p.id AS product_id, p.title AS product_title, p.image_path,
               u.display_name AS seller_name
        FROM orders o
        JOIN products p ON p.id = o.product_id
        JOIN users u ON u.id = o.seller_id
        WHERE o.buyer_id = ?
        ORDER BY o.id DESC
        LIMIT 100
        """,
        (me["id"],),
    ).fetchall()
    return render_template("payments/orders.html", orders=orders)


@bp.route("/transfer", methods=("GET", "POST"))
@login_required
def transfer():
    me = current_user()

    if request.method == "POST":
        # 송금 시도 자체를 레이트리밋 (자동화 남용 방지)
        if rate_limit(f"transfer:{me['id']}", max_calls=10, per_seconds=60):
            flash("송금 시도가 너무 잦습니다. 잠시 후 다시 시도하세요.")
            return redirect(url_for("payments.transfer"))

        recipient_name = (request.form.get("recipient") or "").strip()
        password = request.form.get("password") or ""

        try:
            amount = validate_amount(request.form.get("amount"))
            memo = validate_text(request.form.get("memo"), "transfer_memo", allow_empty=True)
        except ValueError as exc:
            flash(str(exc))
            return render_template("payments/transfer.html", form=request.form), 400

        # 재인증: 비밀번호가 맞아야 송금 진행
        if not check_password_hash(me["password_hash"], password):
            flash("비밀번호가 올바르지 않아 송금을 취소했습니다.")
            return render_template("payments/transfer.html", form=request.form), 401

        # 수취인 조회 (읽기 전용 연결로 존재/상태만 먼저 확인)
        rdb = get_db()
        recipient = rdb.execute(
            "SELECT id, status FROM users WHERE username = ?", (recipient_name,)
        ).fetchone()
        if recipient is None or recipient["status"] != "active":
            flash("존재하지 않거나 이용이 제한된 사용자입니다.")
            return render_template("payments/transfer.html", form=request.form), 404
        if recipient["id"] == me["id"]:
            flash("자기 자신에게는 송금할 수 없습니다.")
            return render_template("payments/transfer.html", form=request.form), 400

        # --- 원자적 이체 ---
        ok, message = _do_transfer(me["id"], recipient["id"], amount, memo)
        flash(message)
        if ok:
            return redirect(url_for("payments.wallet"))
        return render_template("payments/transfer.html", form=request.form), 400

    return render_template("payments/transfer.html")


@bp.route("/buy/<int:product_id>", methods=("POST",))
@login_required
def buy(product_id):
    """상품 가격만큼 결제하되, 대금을 바로 판매자에게 주지 않고 '보류(에스크로)'한다.

    - 금액을 입력받지 않는다. 언제나 '상품 가격' 만큼만 빠진다.
    - 잔액이 상품 가격 이상이면 대금을 보류하고 상품을 거래중 상태로 바꾼다.
    - 구매자가 '구매 확정'을 눌러야 판매자에게 정산된다(선입금 사기 방지).
    - 잔액이 부족하면 충전 화면으로 보낸다(부족분 자동 입력).
    """
    me = current_user()
    db = get_db()
    product = db.execute(
        "SELECT id, title, price, seller_id, status FROM products WHERE id = ?",
        (product_id,),
    ).fetchone()
    if product is None:
        abort(404)

    back = url_for("products.detail", product_id=product_id)

    if rate_limit(f"transfer:{me['id']}", max_calls=15, per_seconds=60):
        flash("결제 시도가 너무 잦습니다. 잠시 후 다시 시도하세요.")
        return redirect(back)

    if product["seller_id"] == me["id"]:
        flash("본인 상품은 구매할 수 없습니다.")
        return redirect(back)
    if product["status"] != "active":
        flash("이미 판매되었거나 거래 중인 상품입니다.")
        return redirect(back)

    price = product["price"]
    if me["balance"] < price:
        shortfall = price - me["balance"]
        flash(f"잔액이 부족합니다. {shortfall:,}원을 충전한 뒤 다시 결제해 주세요.")
        return redirect(url_for("payments.wallet", need=min(shortfall, 1_000_000)))

    status, message, shortfall = _do_hold(me["id"], product_id)
    if status == "insufficient":
        flash(f"잔액이 부족합니다. {shortfall:,}원을 충전한 뒤 다시 결제해 주세요.")
        return redirect(url_for("payments.wallet", need=min(shortfall, 1_000_000)))

    flash(message)
    if status == "ok":
        note = (f"[결제 보류] '{product['title']}' 상품을 {price:,}원에 결제했습니다. "
                "물건을 받은 뒤 구매 확정을 눌러 주세요.")
        db.execute(
            "INSERT INTO messages (product_id, sender_id, receiver_id, body) VALUES (?, ?, ?, ?)",
            (product_id, me["id"], product["seller_id"], note),
        )
        db.commit()
    return redirect(back)


@bp.route("/orders/<int:order_id>/confirm", methods=("POST",))
@login_required
def confirm_order(order_id):
    """구매자가 물건 수령을 확정 → 보류 대금이 판매자에게 정산된다."""
    me = current_user()
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if order is None:
        abort(404)
    if order["buyer_id"] != me["id"]:      # 확정은 구매자만
        abort(403)
    back = url_for("products.detail", product_id=order["product_id"])
    if order["status"] != "held":
        flash("이미 처리된 주문입니다.")
        return redirect(back)

    ok, message = _settle_order(order_id)
    flash(message)
    return redirect(back)


@bp.route("/orders/<int:order_id>/cancel", methods=("POST",))
@login_required
def cancel_order(order_id):
    """구매자 또는 판매자가 보류 중인 거래를 취소 → 구매자에게 환불."""
    me = current_user()
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if order is None:
        abort(404)
    if me["id"] not in (order["buyer_id"], order["seller_id"]):  # 당사자만
        abort(403)
    back = url_for("products.detail", product_id=order["product_id"])
    if order["status"] != "held":
        flash("이미 처리된 주문입니다.")
        return redirect(back)

    ok, message = _refund_order(order_id)
    flash(message)
    return redirect(back)


def _do_hold(buyer_id, product_id):
    """결제 대금을 보류(에스크로)한다. 하나의 IMMEDIATE 트랜잭션.

    상품 상태 확인 → 잔액 확인 → 구매자 차감 → 주문(held) 생성 → 상품 거래중 처리.
    동시에 두 명이 같은 상품을 사도 한 명만 성공한다(중복 판매 방지).
    반환: (상태, 메시지, 부족분)  상태 = 'ok'|'insufficient'|'unavailable'|'error'
    """
    conn = get_write_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        product = conn.execute(
            "SELECT seller_id, price, status FROM products WHERE id = ?",
            (product_id,),
        ).fetchone()
        if product is None or product["status"] != "active":
            conn.execute("ROLLBACK")
            return "unavailable", "이미 판매되었거나 거래 중인 상품입니다.", 0
        seller_id = product["seller_id"]
        price = product["price"]
        if seller_id == buyer_id:
            conn.execute("ROLLBACK")
            return "unavailable", "본인 상품은 구매할 수 없습니다.", 0
        seller = conn.execute(
            "SELECT status FROM users WHERE id = ?", (seller_id,)
        ).fetchone()
        if seller is None or seller["status"] != "active":
            conn.execute("ROLLBACK")
            return "unavailable", "판매자가 이용 제한 상태입니다.", 0
        buyer = conn.execute(
            "SELECT balance FROM users WHERE id = ?", (buyer_id,)
        ).fetchone()
        if buyer is None:
            conn.execute("ROLLBACK")
            return "error", "구매자 정보를 찾을 수 없습니다.", 0
        if buyer["balance"] < price:
            conn.execute("ROLLBACK")
            return "insufficient", "잔액이 부족합니다.", price - buyer["balance"]

        # 대금 보류: 구매자 잔액에서 빼서 플랫폼이 잡아 둔다(판매자에겐 아직 안 줌).
        if price > 0:
            conn.execute("UPDATE users SET balance = balance - ? WHERE id = ?",
                         (price, buyer_id))
        conn.execute(
            """INSERT INTO orders (product_id, buyer_id, seller_id, amount, status)
               VALUES (?, ?, ?, ?, 'held')""",
            (product_id, buyer_id, seller_id, price),
        )
        # 다른 사람이 못 사도록 거래중(=sold) 처리. 취소되면 다시 active 로 돌린다.
        conn.execute("UPDATE products SET status = 'sold' WHERE id = ?", (product_id,))
        conn.execute("COMMIT")
        return "ok", f"{price:,}원이 결제(보류)되었습니다. 수령 후 '구매 확정'을 눌러 주세요.", 0
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return "error", "결제 처리 중 오류가 발생했습니다. 다시 시도해 주세요.", 0
    finally:
        conn.close()


def _settle_order(order_id):
    """보류 대금을 판매자에게 정산하고 주문을 확정한다."""
    conn = get_write_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        order = conn.execute(
            "SELECT * FROM orders WHERE id = ?", (order_id,)
        ).fetchone()
        if order is None or order["status"] != "held":
            conn.execute("ROLLBACK")
            return False, "이미 처리된 주문입니다."
        amount = order["amount"]
        if amount > 0:
            conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
                         (amount, order["seller_id"]))
            conn.execute(
                """INSERT INTO transfers (sender_id, receiver_id, amount, memo)
                   VALUES (?, ?, ?, ?)""",
                (order["buyer_id"], order["seller_id"], amount,
                 f"상품 결제 확정 #{order['product_id']}"),
            )
        conn.execute(
            "UPDATE orders SET status = 'confirmed', confirmed_at = datetime('now') WHERE id = ?",
            (order_id,),
        )
        # 상품은 이미 sold 상태 유지
        conn.execute("COMMIT")
        return True, "구매를 확정했습니다. 판매자에게 정산되었어요. 후기를 남겨 보세요."
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return False, "확정 처리 중 오류가 발생했습니다."
    finally:
        conn.close()


def _refund_order(order_id):
    """보류 대금을 구매자에게 환불하고 상품을 다시 판매중으로 되돌린다."""
    conn = get_write_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        order = conn.execute(
            "SELECT * FROM orders WHERE id = ?", (order_id,)
        ).fetchone()
        if order is None or order["status"] != "held":
            conn.execute("ROLLBACK")
            return False, "이미 처리된 주문입니다."
        amount = order["amount"]
        if amount > 0:
            conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
                         (amount, order["buyer_id"]))
        conn.execute("UPDATE orders SET status = 'cancelled' WHERE id = ?", (order_id,))
        # 차단되지 않은 상품이면 다시 판매중으로
        conn.execute(
            "UPDATE products SET status = 'active' WHERE id = ? AND status = 'sold'",
            (order["product_id"],),
        )
        conn.execute("COMMIT")
        return True, "거래를 취소하고 결제 대금을 환불했습니다."
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return False, "취소 처리 중 오류가 발생했습니다."
    finally:
        conn.close()


@bp.route("/orders/<int:order_id>/review", methods=("POST",))
@login_required
def review_order(order_id):
    """구매 확정된 거래에 대해 구매자가 판매자 후기를 남긴다."""
    me = current_user()
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if order is None:
        abort(404)
    if order["buyer_id"] != me["id"]:
        abort(403)
    back = url_for("products.detail", product_id=order["product_id"])
    if order["status"] != "confirmed":
        flash("구매 확정 후에만 후기를 남길 수 있습니다.")
        return redirect(back)

    try:
        rating = validate_rating(request.form.get("rating"))
        comment = validate_text(request.form.get("comment"), "review_comment",
                                allow_empty=True)
    except ValueError as exc:
        flash(str(exc))
        return redirect(back)

    try:
        db.execute(
            """INSERT INTO reviews (order_id, reviewer_id, target_id, rating, comment)
               VALUES (?, ?, ?, ?, ?)""",
            (order_id, me["id"], order["seller_id"], rating, comment),
        )
        db.commit()
        flash("후기를 남겼습니다. 고맙습니다!")
    except sqlite3.IntegrityError:
        db.rollback()
        flash("이미 후기를 남긴 거래입니다.")
    return redirect(back)


def _do_transfer(sender_id, receiver_id, amount, memo):
    """하나의 IMMEDIATE 트랜잭션에서 잔액 검증 + 이체 + 기록.

    반환: (성공여부, 사용자에게 보여줄 메시지)
    """
    conn = get_write_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")

        sender = conn.execute(
            "SELECT balance, status FROM users WHERE id = ?", (sender_id,)
        ).fetchone()
        receiver = conn.execute(
            "SELECT status FROM users WHERE id = ?", (receiver_id,)
        ).fetchone()

        # 트랜잭션 안에서 상태를 다시 확인 (읽기와 쓰기 사이 변경 방지)
        if sender is None or sender["status"] != "active":
            conn.execute("ROLLBACK")
            return False, "송금할 수 없는 계정 상태입니다."
        if receiver is None or receiver["status"] != "active":
            conn.execute("ROLLBACK")
            return False, "수취인이 이용 제한 상태입니다."
        if sender["balance"] < amount:
            conn.execute("ROLLBACK")
            return False, "잔액이 부족합니다."

        conn.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?",
            (amount, sender_id),
        )
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (amount, receiver_id),
        )
        conn.execute(
            """INSERT INTO transfers (sender_id, receiver_id, amount, memo)
               VALUES (?, ?, ?, ?)""",
            (sender_id, receiver_id, amount, memo),
        )
        conn.execute("COMMIT")
        return True, f"{amount:,}원을 송금했습니다."
    except Exception:
        # CHECK 제약(balance >= 0) 위반 등 어떤 오류든 전체 롤백
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return False, "송금 처리 중 오류가 발생했습니다. 다시 시도해 주세요."
    finally:
        conn.close()


@bp.route("/topup", methods=("POST",))
@login_required
def topup():
    """데모용 충전. 실제 결제 연동 대신, 테스트를 위해 잔액을 추가한다.

    실서비스라면 PG(결제대행) 승인 결과를 검증한 뒤에만 잔액을 올려야 한다.
    여기서는 한도를 두고, 금액 검증을 동일하게 적용한다.
    """
    me = current_user()
    if rate_limit(f"topup:{me['id']}", max_calls=5, per_seconds=60):
        flash("충전 시도가 너무 잦습니다.")
        return redirect(url_for("payments.wallet"))
    try:
        amount = validate_amount(request.form.get("amount"))
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("payments.wallet"))
    if amount > 1_000_000:
        flash("1회 충전 한도는 100만 원입니다.")
        return redirect(url_for("payments.wallet"))

    conn = get_write_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        # 데모 충전이 무한정 잔액을 만들지 못하도록 계정 잔액 총액에 상한을 둔다.
        row = conn.execute("SELECT balance FROM users WHERE id = ?",
                           (me["id"],)).fetchone()
        if row["balance"] + amount > MAX_WALLET_BALANCE:
            conn.execute("ROLLBACK")
            flash(f"보유 잔액 한도({MAX_WALLET_BALANCE:,}원)를 초과할 수 없습니다.")
            return redirect(url_for("payments.wallet"))
        conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
                     (amount, me["id"]))
        conn.execute("COMMIT")
        flash(f"{amount:,}원을 충전했습니다.")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        flash("충전 중 오류가 발생했습니다.")
    finally:
        conn.close()
    return redirect(url_for("payments.wallet"))
