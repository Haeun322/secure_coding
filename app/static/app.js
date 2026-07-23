// CSP(script-src 'self')를 지키기 위해 인라인 이벤트 핸들러 대신 외부 스크립트에서 처리한다.
// data-confirm 속성이 있는 폼은 제출 전 확인 창을 띄운다.
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.getAttribute('data-confirm'))) {
        e.preventDefault();
      }
    });
  });

  // data-autosubmit: 값이 바뀌면 소속 폼을 자동 제출(필터/정렬 편의)
  document.querySelectorAll('[data-autosubmit]').forEach(function (el) {
    el.addEventListener('change', function () {
      if (el.form) { el.form.submit(); }
    });
  });

  // 알림 드롭다운 토글
  var bell = document.querySelector('[data-notif-toggle]');
  var panel = document.querySelector('[data-notif-panel]');
  if (bell && panel) {
    bell.addEventListener('click', function (e) {
      e.stopPropagation();
      panel.hidden = !panel.hidden;
    });
    panel.addEventListener('click', function (e) { e.stopPropagation(); });
    document.addEventListener('click', function () {
      if (!panel.hidden) { panel.hidden = true; }
    });
  }

  // --- 실시간 알림 폴링 ---
  function renderNotif(data) {
    var badge = document.querySelector('[data-notif-count]');
    if (badge) {
      if (data.unread > 0) { badge.textContent = data.unread; badge.hidden = false; }
      else { badge.hidden = true; }
    }
    var head = document.querySelector('[data-notif-headcount]');
    if (head) { head.textContent = data.unread; }
    var list = document.querySelector('[data-notif-list]');
    if (list) {
      list.textContent = '';
      if (!data.items || data.items.length === 0) {
        var empty = document.createElement('span');
        empty.className = 'notif-empty muted';
        empty.textContent = '새 알림이 없습니다.';
        list.appendChild(empty);
      } else {
        data.items.forEach(function (it) {
          var a = document.createElement('a');
          a.className = 'notif-item' + (it.is_read ? '' : ' unread');
          // href 는 정수 id 로만 구성(사용자 입력을 URL 에 넣지 않음)
          a.setAttribute('href', '/notifications/' + encodeURIComponent(it.id) + '/go');
          var t = document.createElement('span');
          t.className = 'notif-text';
          t.textContent = it.text;              // XSS 안전(textContent)
          var s = document.createElement('small');
          s.className = 'muted';
          s.textContent = it.created_at;
          a.appendChild(t); a.appendChild(s);
          list.appendChild(a);
        });
      }
    }
  }
  if (bell) {
    var pollNotif = function () {
      fetch('/notifications/summary', { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { if (d) renderNotif(d); })
        .catch(function () {});
    };
    setInterval(pollNotif, 12000);
  }

  // --- 실시간 채팅(대화방에서 새 메시지 자동 표시) ---
  var log = document.querySelector('[data-chat-log]');
  if (log) {
    var pid = log.getAttribute('data-product');
    var peer = log.getAttribute('data-peer');
    var meId = log.getAttribute('data-me');
    var lastId = function () {
      var items = log.querySelectorAll('[data-mid]');
      return items.length ? items[items.length - 1].getAttribute('data-mid') : '0';
    };
    log.scrollTop = log.scrollHeight;
    var pollChat = function () {
      fetch('/chat/' + encodeURIComponent(pid) + '/' + encodeURIComponent(peer) +
            '/messages?after=' + encodeURIComponent(lastId()), { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d || !d.messages || !d.messages.length) { return; }
          var empty = log.querySelector('.chat-empty');
          if (empty) { empty.remove(); }
          d.messages.forEach(function (m) {
            var div = document.createElement('div');
            div.className = 'msg' + (String(m.sender_id) === meId ? ' mine' : '');
            div.setAttribute('data-mid', m.id);
            var b = document.createElement('div');
            b.textContent = m.body;               // XSS 안전
            var meta = document.createElement('div');
            meta.className = 'meta';
            meta.textContent = m.created_at;
            div.appendChild(b); div.appendChild(meta);
            log.appendChild(div);
          });
          log.scrollTop = log.scrollHeight;
        })
        .catch(function () {});
    };
    setInterval(pollChat, 4000);
  }
});
