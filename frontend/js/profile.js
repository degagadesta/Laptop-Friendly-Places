import { auth, requireAuth } from './auth.js';
import { API_CONFIG } from './apiConfig.js';

if (!requireAuth()) { /* requireAuth redirects */ }

async function loadProfile() {
  try {
    const res = await fetch(API_CONFIG.BASE_URL + API_CONFIG.ENDPOINTS.PROFILE, {
      headers: { 'Authorization': `Bearer ${auth.token}` }
    });
    const data = await res.json();
    const user = data.user || auth.getCurrentUser();
    renderProfile(user);
  } catch (err) {
    // Fallback to cached user data
    renderProfile(auth.getCurrentUser());
  }
}

function renderProfile(user) {
  if (!user) { window.location.replace('login.html'); return; }

  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

  set('profileName', user.name || 'User');
  set('profileEmail', user.email || '');
  set('infoName', user.name || 'User');
  set('infoEmail', user.email || '');
  set('memberSince', user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown');
  set('contributionCount', '0');

  // Favorites count — fetch from API
  fetch(API_CONFIG.BASE_URL + '/favorites', {
    headers: { 'Authorization': `Bearer ${auth.token}` }
  })
    .then(r => r.json())
    .then(data => { set('favCount', Array.isArray(data) ? data.length : 0); })
    .catch(() => { set('favCount', '0'); });
}

loadProfile();

// Logout
const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
  logoutBtn.addEventListener('click', () => {
    auth.logout();
    window.location.replace('login.html');
  });
}

const profileIcon = document.getElementById('profile');
if (profileIcon) profileIcon.addEventListener('click', () => { window.location.href = 'profile.html'; });

const headerProfile = document.getElementById('headerProfile');
if (headerProfile) headerProfile.addEventListener('click', () => { window.location.href = 'profile.html'; });
