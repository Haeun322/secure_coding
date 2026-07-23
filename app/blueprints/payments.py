"""사용자 간 송금.

돈을 다루므로 가장 방어적으로 구현한다.
- 금액은 양의 정수(원)만 허용
- 비밀번호 재확인(재인증)
- 자기 자신에게 송금 불가 / 차단 사용자에게 송금 불가
- 잔액 확인과 차감/증가를 하나의 IMMEDIATE 트랜잭션 안에서 처리(경쟁 조건/이중지불 방지)
- DB 의 CHECK(balance >= 0) 제약이 마지막 안전망
"""
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import check_password_hash

from ..db import get_db, get_write_connection
from ..security import current_user, login_required, rate_limit
from ..validators import validate_amount, validate_text

bp = Blueprint("payments", __name__, url_prefix="/wallet")


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
