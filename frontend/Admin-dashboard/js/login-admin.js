document.addEventListener('DOMContentLoaded', function () {
  // Check if already logged in as admin (use separate admin keys)
  const adminToken = localStorage.getItem('lfp_admin_token');
  const adminUser = JSON.parse(localStorage.getItem('lfp_admin_data') || 'null');
  if (adminToken && adminUser?.role === 'admin') {
    window.location.href = 'index.html';
    return;
  }

  const loginForm = document.getElementById('loginForm');
  const errorMessage = document.getElementById('errorMessage');

  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();

    const email = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    errorMessage.textContent = '';

    try {
      const res = await fetch('http://localhost:8000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (!res.ok) {
        errorMessage.textContent = data.error || 'Login failed';
        loginForm.classList.add('shake');
        setTimeout(() => loginForm.classList.remove('shake'), 500);
        return;
      }

      // Check if user is admin
      if (data.user?.role !== 'admin') {
        errorMessage.textContent = 'Access denied. Admin account required.';
        return;
      }

      // Store admin credentials with separate keys
      localStorage.setItem('lfp_admin_token', data.token);
      localStorage.setItem('lfp_admin_data', JSON.stringify(data.user));
      localStorage.setItem('adminLoggedIn', 'true');
      localStorage.setItem('adminUsername', data.user.name || data.user.email);

      window.location.href = 'index.html';

    } catch (err) {
      errorMessage.textContent = 'Connection error. Is the server running?';
    }
  });
});
