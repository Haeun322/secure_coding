"""신고 기능.

사용자가 악성 유저나 상품을 신고한다. 관리자는 admin 화면에서 처리한다.
자동 임계치: 서로 다른 사용자로부터 신고가 일정 수 이상 쌓이면 자동으로 숨김
처리(blocked)하여 관리자 확인 전이라도 피해 확산을 막는다.
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

bp = Blueprint("reports", __name__, url_prefix="/report")

AUTO_BLOCK_THRESHOLD = 3  # 서로 다른 신고자 수


@bp.route("/<target_type>/<int:target_id>", methods=("GET", "POST"))
@login_required
def create(target_type, target_id):
    if target_type not in ("user", "product"):
        abort(404)

    me = current_user()
    db = get_db()

    # 신고 대상이 실제로 존재하는지 확인
    if target_type == "user":
        target = db.execute("SELECT id FROM users WHERE id = ?", (target_id,)).fetchone()
        if target_id == me["id"]:
            flash("자기 자신은 신고할 수 없습니다.")
            return redirect(url_for("main.index"))
    else:
        target = db.execute("SELECT id FROM products WHERE id = ?", (target_id,)).fetchone()
    if target is None:
        abort(404)

    if request.method == "POST":
        if rate_limit(f"report:{me['id']}", max_calls=10, per_seconds=3600):
            flash("신고가 너무 많습니다. 잠시 후 다시 시도하세요.")
            return redirect(url_for("main.index"))
        try:
            reason = validate_text(request.form.get("reason"), "report_reason")
        except ValueError as exc:
            flash(str(exc))
            return render_template("reports/form.html",
                                   target_type=target_type, target_id=target_id), 400

        try:
            db.execute(
                """INSERT INTO reports (reporter_id, target_type, target_id, reason)
                   VALUES (?, ?, ?, ?)""",
                (me["id"], target_type, target_id, reason),
            )
            db.commit()
        except Exception:
            # UNIQUE 제약: 같은 대상 중복 신고
            db.rollback()
            flash("이미 신고한 대상입니다.")
            return redirect(url_for("main.index"))

        _maybe_auto_block(db, target_type, target_id)
        flash("신고가 접수되었습니다. 검토 후 조치하겠습니다.")
        return redirect(url_for("main.index"))

    return render_template("reports/form.html",
                           target_type=target_type, target_id=target_id)


def _maybe_auto_block(db, target_type, target_id):
    """서로 다른 신고자 수가 임계치 이상이면 자동 숨김."""
    row = db.execute(
        """SELECT COUNT(DISTINCT reporter_id) AS c FROM reports
           WHERE target_type = ? AND target_id = ? AND status = 'open'""",
        (target_type, target_id),
    ).fetchone()
    if row["c"] < AUTO_BLOCK_THRESHOLD:
        return

    if target_type == "product":
        db.execute("UPDATE products SET status = 'blocked' WHERE id = ?", (target_id,))
    else:
        # 관리자 계정은 자동 차단 대상에서 제외
        db.execute(
            "UPDATE users SET status = 'blocked' WHERE id = ? AND role != 'admin'",
            (target_id,),
        )
    db.commit()
