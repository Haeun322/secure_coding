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
});
