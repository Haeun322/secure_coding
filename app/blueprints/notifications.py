"""알림.

- add_notification(): 다른 모듈(chat, payments)에서 이벤트가 생길 때 호출한다.
- 목록/모두읽음/개별이동 라우트.
- 헤더의 종 아이콘 배지와 드롭다운은 __init__ 의 context_processor 가 채운다.
"""
from urllib.parse import urlparse

from flask import (
    Blueprint,
    abort,
    redirect,
    request,
    render_template,
    url_for,
)

from ..db import get_db
from ..security import current_user, login_required

bp = Blueprint("notifications", __name__, url_prefix="/notifications")


def add_notification(db, user_id, text, link=""):
    """user_id 에게 알림을 추가한다. text 최대 200자, link 는 내부 경로만."""
    text = (text or "")[:200]
    if not _is_internal(link):
        link = ""
    db.execute(
        "INSERT INTO notifications (user_id, text, link) VALUES (?, ?, ?)",
        (user_id, text, link),
    )


def _is_internal(target):
    """저장/이동 링크는 같은 사이트 내부 경로만 허용(오픈 리다이렉트 방지)."""
    if not target:
        return False
    if "\\" in target or "\n" in target or "\r" in target:
        return False
    parsed = urlparse(target)
    return (not parsed.scheme and not parsed.netloc
            and target.startswith("/") and not target.startswith("//"))


@bp.route("/")
@login_required
def index():
    me = current_user()
    rows = get_db().execute(
        """SELECT id, text, link, is_read, created_at
           FROM notifications WHERE user_id = ?
           ORDER BY id DESC LIMIT 100""",
        (me["id"],),
    ).fetchall()
    return render_template("notifications/index.html", notifications=rows)


@bp.route("/read-all", methods=("POST",))
@login_required
def read_all():
    me = current_user()
    db = get_db()
    db.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0",
               (me["id"],))
    db.commit()
    # 원래 보던 페이지로 돌아간다(같은 사이트일 때만)
    ref = request.referrer or ""
    if ref.startswith(request.host_url):
        return redirect(ref)
    return redirect(url_for("notifications.index"))


@bp.route("/<int:notif_id>/go", methods=("GET",))
@login_required
def go(notif_id):
    """알림을 읽음 처리하고 대상 링크로 이동."""
    me = current_user()
    db = get_db()
    n = db.execute("SELECT id, user_id, link FROM notifications WHERE id = ?",
                   (notif_id,)).fetchone()
    if n is None:
        abort(404)
    if n["user_id"] != me["id"]:      # 남의 알림 조작 차단(IDOR)
        abort(403)
    db.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notif_id,))
    db.commit()
    if _is_internal(n["link"]):
        return redirect(n["link"])
    return redirect(url_for("notifications.index"))
