// public/auth.js
function switchTab(n) {
  document.getElementById('login-form').classList.toggle('hidden', n === 1);
  document.getElementById('register-form').classList.toggle('hidden', n === 0);
  document.getElementById('tab-login').classList.toggle('border-emerald-500', n === 0);
  document.getElementById('tab-login').classList.toggle('text-white', n === 0);
  document.getElementById('tab-login').classList.toggle('text-gray-400', n === 1);
  document.getElementById('tab-register').classList.toggle('border-emerald-500', n === 1);
  document.getElementById('tab-register').classList.toggle('text-white', n === 1);
  document.getElementById('tab-register').classList.toggle('text-gray-400', n === 0);
}

async function handleLogin(e) {
  e.preventDefault();
  const errorEl = document.getElementById('login-error');
  errorEl.classList.add('hidden');

  const identifier = document.getElementById('login-identifier').value.trim();
  const password = document.getElementById('login-password').value;

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, password })
  });

  const data = await res.json();
  if (!res.ok) {
    errorEl.textContent = data.error || 'Login failed';
    errorEl.classList.remove('hidden');
    return;
  }

  window.location.href = '/';
}

async function handleRegister(e) {
  e.preventDefault();
  const errorEl = document.getElementById('register-error');
  errorEl.classList.add('hidden');

  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm = document.getElementById('reg-confirm').value;

  if (password !== confirm) {
    errorEl.textContent = 'Passwords do not match';
    errorEl.classList.remove('hidden');
    return;
  }

  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password, confirmPassword: confirm })
  });

  const data = await res.json();
  if (!res.ok) {
    errorEl.textContent = data.error || 'Registration failed';
    errorEl.classList.remove('hidden');
    return;
  }

  alert('Account created! Please login.');
  switchTab(0);
}
