document.querySelectorAll('[data-reveal]').forEach(button => {
  button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.reveal);
    input.type = input.type === 'password' ? 'text' : 'password';
    const isVisible = input.type === 'text';
    button.textContent = isVisible ? 'Hide password' : 'Show password';
    button.setAttribute('aria-pressed', String(isVisible));
    if (input.type === 'text') {
      const note = document.createElement('small');
      note.className = 'reveal-warning';
      note.textContent = '👁 Make sure nobody nearby can see your password.';
      input.closest('label').appendChild(note);
      setTimeout(() => note.remove(), 3000);
    }
  });
});

const password = document.getElementById('password');
if (password) {
  password.addEventListener('input', () => {
    const value = password.value;
    const tests = [value.length >= 8, /[A-Z]/.test(value), /[a-z]/.test(value), /\d/.test(value), /[^A-Za-z0-9]/.test(value)];
    const score = tests.filter(Boolean).length;
    const label = document.getElementById('strength-label');
    const bar = document.getElementById('strength-bar');
    const help = document.getElementById('strength-help');
    const levels = [['Start typing', 0, ''], ['Weak', 20, 'weak'], ['Weak', 40, 'weak'], ['Getting better', 60, 'medium'], ['Strong', 80, 'strong'], ['Excellent', 100, 'strong']];
    const [word, width, state] = levels[score];
    label.textContent = word; label.className = state; bar.style.width = width + '%'; bar.className = state;
    document.getElementById('strength-score').textContent = width + '%';
    ['length', 'upper', 'lower', 'number', 'symbol'].forEach((name, index) => {
      const rule = document.getElementById('rule-' + name);
      rule.classList.toggle('met', tests[index]);
      rule.textContent = (tests[index] ? '✓ ' : '○ ') + rule.textContent.slice(2);
    });
    help.textContent = score === 5 ? 'Excellent — every requirement is met. Your password is ready.' : 'Complete all five checks to create a strong password.';
  });
}

const confirmPassword = document.getElementById('confirm-password');
if (password && confirmPassword) {
  const validateConfirmation = () => {
    confirmPassword.setCustomValidity(
      confirmPassword.value && confirmPassword.value !== password.value ? 'Passwords do not match.' : ''
    );
  };
  password.addEventListener('input', validateConfirmation);
  confirmPassword.addEventListener('input', validateConfirmation);
}

const scoreNumber = document.querySelector('.score-ring b');
if (scoreNumber) {
  const targetScore = 92;
  const ring = scoreNumber.closest('.score-ring');
  const start = performance.now();
  const duration = 1300;
  const animateScore = now => {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    scoreNumber.textContent = Math.round(targetScore * eased);
    ring.style.setProperty('--score-fill', `${targetScore * eased}%`);
    if (progress < 1) requestAnimationFrame(animateScore);
    else ring.classList.add('bounce');
  };
  requestAnimationFrame(animateScore);
}

const themeToggle = document.getElementById('theme-toggle');
if (localStorage.getItem('secureauth-theme') === 'dark') document.documentElement.classList.add('theme-dark');
if (themeToggle) themeToggle.addEventListener('click', () => {
  document.documentElement.classList.toggle('theme-dark');
  localStorage.setItem('secureauth-theme', document.documentElement.classList.contains('theme-dark') ? 'dark' : 'light');
});
