let allPlaces = [];
let currentFilter = 'all';

document.addEventListener('DOMContentLoaded', function () {
  if (!initPage()) return;
  loadPlaces();
  setupEventListeners();

  setTimeout(() => {
    if (window.mapsModule?.initializeMaps) {
      window.mapsModule.initializeMaps();
      setTimeout(() => { if (window.loadPlacesMap) window.loadPlacesMap('all'); }, 500);
    }
  }, 500);
});

async function loadPlaces(searchQuery = '') {
  try {
    const res = await ADMIN_API.get('/admin/places');
    allPlaces = res.places || [];

    let filtered = allPlaces;
    // Fix: 'verified' should filter for 'approved' status
    if (currentFilter === 'verified' || currentFilter === 'approved') {
      filtered = filtered.filter(p => p.status === 'approved');
    }
    if (currentFilter === 'pending') {
      filtered = filtered.filter(p => p.status === 'pending');
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(p =>
        (p.name || '').toLowerCase().includes(q) ||
        (p.location || '').toLowerCase().includes(q)
      );
    }

    const table = document.getElementById('placesTable');
    const noPlaces = document.getElementById('noPlaces');
    const countEl = document.getElementById('placesCount');

    if (!table) {
      console.error('placesTable element not found');
      return;
    }

    if (countEl) countEl.textContent = filtered.length;
    table.innerHTML = '';

    if (!filtered.length) { if (noPlaces) noPlaces.style.display = 'block'; return; }
    if (noPlaces) noPlaces.style.display = 'none';

    filtered.forEach(place => {
      const statusClass = place.status === 'approved' ? 'status-verified' : 'status-pending';
      const statusText = place.status === 'approved' ? 'Approved' : 'Pending';
      const avg = (((place.wifi_rating || 0) + (place.power_rating || 0) + (place.service_rating || 0)) / 3).toFixed(1);

      // Format location to be shorter
      let locationDisplay = 'N/A';
      if (place.location) {
        const coords = place.location.split(',');
        if (coords.length === 2) {
          const lat = parseFloat(coords[0]).toFixed(4);
          const lng = parseFloat(coords[1]).toFixed(4);
          locationDisplay = `${lat}, ${lng}`;
        } else {
          locationDisplay = place.location.substring(0, 20) + '...';
        }
      }

      const row = document.createElement('tr');
      row.innerHTML = `
                <td>
                    <div style="display:flex;align-items:center;gap:12px;">
                        <div>
                            <div style="font-weight:600;">${place.name}</div>
                            <div style="font-size:12px;color:var(--gray-600);">${(place.description || '').substring(0, 50)}...</div>
                        </div>
                    </div>
                </td>
                <td>${place.category || 'Other'}</td>
                <td title="${place.location || 'N/A'}">${locationDisplay}</td>
                <td>${avg}/5</td>
                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                <td>${place.created_at ? new Date(place.created_at).toLocaleDateString() : 'N/A'}</td>
                <td>
                    ${place.status !== 'approved' ? `<button class="action-btn btn-approve" onclick="approvePlace(${place.id})"><i class="fas fa-check"></i> Approve</button>` : ''}
                    <button class="action-btn btn-view" onclick="viewPlace(${place.id})"><i class="fas fa-eye"></i></button>
                    <button class="action-btn btn-reject" onclick="deletePlace(${place.id})"><i class="fas fa-trash"></i></button>
                </td>`;
      table.appendChild(row);
    });
  } catch (err) {
    console.error('Error loading places:', err);
    showToast('Failed to load places', 'error');
  }
}

async function approvePlace(placeId) {
  try {
    await ADMIN_API.post('/admin/places/approve', { place_id: placeId });
    showToast('Place approved!', 'success');
    loadPlaces();
  } catch (err) { showToast('Failed to approve place', 'error'); }
}

function deletePlace(placeId) {
  if (!confirm('Delete this place permanently?')) return;
  confirmDeletePlace(placeId);
}

async function confirmDeletePlace(placeId) {
  try {
    console.log('Deleting place:', placeId);
    const response = await ADMIN_API.del('/admin/places/delete', { place_id: placeId });
    console.log('Delete response:', response);
    showToast('Place deleted successfully!', 'success');
    await loadPlaces();

    // Also reload map if it exists
    if (window.loadPlacesMap) {
      window.loadPlacesMap(currentFilter);
    }
  } catch (err) {
    console.error('Delete error:', err);
    showToast('Failed to delete place: ' + err.message, 'error');
  }
}

function viewPlace(placeId) {
  console.log('Viewing place:', placeId);
  const place = allPlaces.find(p => p.id === placeId);

  if (!place) {
    console.error('Place not found:', placeId);
    showToast('Place not found', 'error');
    return;
  }

  const avg = (((place.wifi_rating || 0) + (place.power_rating || 0) + (place.service_rating || 0)) / 3).toFixed(1);
  const modal = document.getElementById('placeModal');
  const body = document.getElementById('placeModalBody');

  if (!modal || !body) {
    console.error('Modal elements not found');
    return;
  }

  // Get image source
  let imageHtml = '';
  if (place.image_url) {
    imageHtml = `<img src="${place.image_url}" alt="${place.name}" style="max-width: 100%; border-radius: 8px; margin-bottom: 15px;">`;
  } else if (place.image) {
    const imgSrc = place.image.startsWith('http') ? place.image : 'http://localhost:8000/' + place.image;
    imageHtml = `<img src="${imgSrc}" alt="${place.name}" style="max-width: 100%; border-radius: 8px; margin-bottom: 15px;">`;
  }

  body.innerHTML = `
    ${imageHtml}
    <h4>${place.name}</h4>
    <p><strong>Category:</strong> ${place.category || 'N/A'}</p>
    <p><strong>Location:</strong> ${place.location || 'N/A'}</p>
    <p><strong>Description:</strong> ${place.description || 'N/A'}</p>
    <p><strong>WiFi:</strong> ${place.wifi_rating || 'N/A'}/5 &nbsp; 
       <strong>Power:</strong> ${place.power_rating || 'N/A'}/5 &nbsp; 
       <strong>Service:</strong> ${place.service_rating || 'N/A'}/5</p>
    <p><strong>Average Rating:</strong> ${avg}/5</p>
    <p><strong>Status:</strong> <span class="status-badge ${place.status === 'approved' ? 'status-verified' : 'status-pending'}">${place.status || 'N/A'}</span></p>
    <p><strong>Created:</strong> ${place.created_at ? new Date(place.created_at).toLocaleString() : 'N/A'}</p>
  `;

  modal.style.display = 'flex';
  console.log('Modal displayed');
}

function closeModal() { document.getElementById('placeModal').style.display = 'none'; }

function filterPlaces(filter) {
  currentFilter = filter;

  // Update active state on filter buttons
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event?.target?.classList.add('active');

  loadPlaces();

  // Also update the map to match the filter
  if (window.loadPlacesMap) {
    window.loadPlacesMap(filter);
  }
}

function setupEventListeners() {
  // Global search (top bar)
  const globalSearch = document.getElementById('globalSearch');
  if (globalSearch) {
    globalSearch.addEventListener('input', e => loadPlaces(e.target.value));
  }

  // Table search (if exists)
  const tableSearch = document.querySelector('input[placeholder="Search places..."]');
  if (tableSearch) {
    tableSearch.addEventListener('input', e => loadPlaces(e.target.value));
  }

  // Close modal on overlay click
  window.addEventListener('click', e => {
    document.querySelectorAll('.modal').forEach(m => {
      if (e.target === m) m.style.display = 'none';
    });
  });
}

// Add searchPlaces function for inline search
function searchPlaces(query) {
  loadPlaces(query);
}

window.searchPlaces = searchPlaces;

function showToast(message, type = 'info') {
  let c = document.getElementById('toast-container');
  if (!c) { c = document.createElement('div'); c.id = 'toast-container'; c.style.cssText = 'position:fixed;top:20px;right:20px;z-index:10000;'; document.body.appendChild(c); }
  const t = document.createElement('div');
  t.style.cssText = `background:${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};color:white;padding:15px 20px;border-radius:8px;margin-bottom:10px;`;
  t.textContent = message;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 3000);
}

window.filterPlaces = filterPlaces;
window.viewPlace = viewPlace;
window.approvePlace = approvePlace;
window.deletePlace = deletePlace;
window.confirmDeletePlace = confirmDeletePlace;
window.closeModal = closeModal;
window.loadPlaces = loadPlaces;
