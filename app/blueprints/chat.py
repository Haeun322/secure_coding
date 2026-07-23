"""사용자 간 1:1 메시지.

접근 통제 원칙: 대화는 참여자(보낸 사람/받는 사람) 본인만 조회할 수 있다.
어떤 쿼리도 '내 id' 를 조건에서 빼지 않는다.
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
    """내가 참여한 대화 상대 목록 + 마지막 메시지."""
    me = current_user()["id"]
    db = get_db()
    # 상대방별 최근 메시지 1건씩. 차단된 상대는 제외.
    rows = db.execute(
        """
        SELECT other.id AS other_id, other.display_name AS other_name,
               m.body AS last_body, m.created_at AS last_at
        FROM messages m
        JOIN users other ON other.id = CASE
                WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
        WHERE (m.sender_id = ? OR m.receiver_id = ?)
          AND other.status = 'active'
          AND m.id IN (
              SELECT MAX(id) FROM messages
              WHERE (sender_id = ? OR receiver_id = ?)
              GROUP BY CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END
          )
        ORDER BY m.created_at DESC
        """,
        (me, me, me, me, me, me),
    ).fetchall()
    return render_template("chat/inbox.html", conversations=rows)


@bp.route("/<int:user_id>", methods=("GET", "POST"))
@login_required
def thread(user_id):
    me = current_user()
    if user_id == me["id"]:
        flash("자기 자신과는 대화할 수 없습니다.")
        return redirect(url_for("chat.inbox"))

    db = get_db()
    other = db.execute(
        "SELECT id, display_name, status FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if other is None or other["status"] != "active":
        abort(404)

    if request.method == "POST":
        # 메시지 도배 방지
        if rate_limit(f"msg:{me['id']}", max_calls=20, per_seconds=60):
            flash("메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도하세요.")
            return redirect(url_for("chat.thread", user_id=user_id))
        try:
            body = validate_text(request.form.get("body"), "message_body")
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("chat.thread", user_id=user_id))
        db.execute(
            "INSERT INTO messages (sender_id, receiver_id, body) VALUES (?, ?, ?)",
            (me["id"], user_id, body),
        )
        db.commit()
        return redirect(url_for("chat.thread", user_id=user_id))

    # 나와 상대 사이의 메시지만 조회 (양방향)
    messages = db.execute(
        """
        SELECT * FROM messages
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
        LIMIT 500
        """,
        (me["id"], user_id, user_id, me["id"]),
    ).fetchall()
    return render_template("chat/thread.html", messages=messages,
                           other=other, me_id=me["id"])
