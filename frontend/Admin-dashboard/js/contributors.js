document.addEventListener('DOMContentLoaded', async function () {
  if (!initPage()) return;
  await loadContributors();
  setupEventListeners();
});

async function loadContributors() {
  try {
    // Use top-contributors endpoint which includes places_count
    const res = await ADMIN_API.get('/users/top-contributors');
    const contributors = res.contributors || [];

    // Filter out users with 0 contributions
    const activeContributors = contributors.filter(c => c.places_count > 0);

    const table = document.getElementById('contributorsTable');
    const noContributors = document.getElementById('noContributors');
    if (!table) return;

    table.innerHTML = '';

    if (!activeContributors.length) {
      if (noContributors) noContributors.style.display = 'block';
      return;
    }
    if (noContributors) noContributors.style.display = 'none';

    activeContributors.forEach(contributor => {
      const row = document.createElement('tr');
      row.innerHTML = `
                <td>
                    <strong>${contributor.name || 'No name'}</strong><br>
                    <small style="color:#666;">ID: ${contributor.id}</small>
                </td>
                <td>${contributor.email || 'No email'}</td>
                <td><span class="status-badge ${contributor.role === 'admin' ? 'status-verified' : 'status-pending'}">${contributor.role || 'user'}</span></td>
                <td>${contributor.created_at ? new Date(contributor.created_at).toLocaleDateString() : 'N/A'}</td>
                <td>
                    <strong style="font-size:18px;color:#4CAF50;">${contributor.places_count}</strong>
                    <span style="color:#666;font-size:13px;"> ${contributor.places_count === 1 ? 'place' : 'places'}</span>
                </td>`;
      table.appendChild(row);
    });
  } catch (err) {
    console.error('Error loading contributors:', err);
    alert('Failed to load contributors.');
  }
}

function setupEventListeners() {
  const search = document.getElementById('globalSearch');
  if (search) {
    search.addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#contributorsTable tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
}

function showToast(message, type = 'info') {
  let c = document.getElementById('toastContainer');
  if (!c) { c = document.createElement('div'); c.id = 'toastContainer'; document.body.appendChild(c); }
  const t = document.createElement('div');
  t.style.cssText = `background:${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};color:white;padding:12px 20px;border-radius:8px;margin-bottom:10px;`;
  t.textContent = message;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 3000);
}

window.loadContributors = loadContributors;
