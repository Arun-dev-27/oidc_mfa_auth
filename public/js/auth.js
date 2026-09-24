// Progressive enhancement only: every form works without this script.
(function () {
  'use strict';

  // Show / hide password.
  document.querySelectorAll('[data-reveal]').forEach(function (button) {
    var input = document.getElementById(button.getAttribute('data-reveal'));
    if (!input) return;
    button.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(show));
      button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
  });

  // Handoff delivery: submit the signed assertion to the target application at once.
  document.querySelectorAll('form[data-autosubmit]').forEach(function (form) {
    var button = form.querySelector('button');
    if (button) button.disabled = true;
    form.submit();
  });

  document.querySelectorAll('[data-auth-form]').forEach(function (form) {
    var submit = form.querySelector('[data-submit]');
    var required = Array.prototype.slice.call(form.querySelectorAll('[required]'));

    // Submit stays disabled until the required fields are filled (as on the RMS login).
    function sync() {
      if (!submit) return;
      submit.disabled = required.some(function (el) {
        return !el.value.trim();
      });
    }
    required.forEach(function (el) {
      el.addEventListener('input', sync);
    });
    sync();

    // Digits only for ITS ID and codes.
    form.querySelectorAll('input[inputmode="numeric"]').forEach(function (el) {
      el.addEventListener('input', function () {
        var digits = el.value.replace(/\D+/g, '');
        if (digits !== el.value) el.value = digits;
        sync();
      });
    });

    // No double submit.
    form.addEventListener('submit', function () {
      if (submit) {
        submit.disabled = true;
        submit.textContent = submit.textContent.trim() === 'Login' ? 'Signing in…' : 'Verifying…';
      }
    });
  });
})();
