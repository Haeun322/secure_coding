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
});
