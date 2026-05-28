document.addEventListener('DOMContentLoaded', async function () {
  if (!initPage()) return;
  await loadReports();
  setupEventListeners();
});

async function loadReports(statusFilter = '') {
  try {
    const url = statusFilter ? `/admin/reports?status=${statusFilter}` : '/admin/reports';
    const res = await ADMIN_API.get(url);
    const reports = res.data || [];

    // Store reports globally for viewReport function
    window.allReports = reports;

    const table = document.getElementById('reportedTable');
    const noReports = document.getElementById('noReports');
    if (!table) return;

    table.innerHTML = '';

    if (!reports.length) {
      if (noReports) noReports.style.display = 'block';
      return;
    }
    if (noReports) noReports.style.display = 'none';

    reports.forEach(report => {
      let statusClass = 'status-reported', statusText = 'Pending';
      if (report.status === 'resolved') { statusClass = 'status-verified'; statusText = 'Resolved'; }
      if (report.status === 'rejected') { statusClass = 'status-rejected'; statusText = 'Rejected'; }

      // Format date properly
      let dateDisplay = 'N/A';
      if (report.created_at) {
        try {
          dateDisplay = new Date(report.created_at).toLocaleDateString();
        } catch (e) {
          dateDisplay = report.created_at;
        }
      }

      // Format message
      const messageDisplay = report.message && report.message.trim() ?
        (report.message.length > 40 ? report.message.substring(0, 40) + '...' : report.message) :
        'No message';

      const row = document.createElement('tr');
      row.innerHTML = `
                <td><strong>${report.place_name || 'Place #' + (report.place_id || 'Unknown')}</strong></td>
                <td>${report.reason || 'Not specified'}</td>
                <td>${report.reported_by || 'Anonymous'}</td>
                <td>${messageDisplay}</td>
                <td>${dateDisplay}</td>
                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                <td>
                    <button class="action-btn btn-view" onclick="viewReport(${report.id})"><i class="fas fa-eye"></i></button>
                    ${report.status === 'pending' ? `
                        <button class="action-btn btn-approve" onclick="updateReport(${report.id},'resolved')"><i class="fas fa-check"></i></button>
                        <button class="action-btn btn-reject"  onclick="updateReport(${report.id},'rejected')"><i class="fas fa-times"></i></button>` : ''}
                </td>`;
      table.appendChild(row);
    });
  } catch (err) {
    console.error('Error loading reports:', err);
    alert('Failed to load reports.');
  }
}

function viewReport(reportId) {
  // Find report from stored data
  const report = window.allReports?.find(r => r.id == reportId);

  if (!report) {
    alert('Report not found');
    return;
  }

  // Create modal overlay
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:10000;';

  // Determine status styling
  let statusClass = 'status-reported', statusText = 'Pending';
  if (report.status === 'resolved') { statusClass = 'status-verified'; statusText = 'Resolved'; }
  if (report.status === 'rejected') { statusClass = 'status-rejected'; statusText = 'Rejected'; }

  // Create modal content
  modal.innerHTML = `
    <div style="background:white;padding:30px;border-radius:15px;width:600px;max-width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 10px 40px rgba(0,0,0,0.2);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
        <h2 style="margin:0;color:#1a1a1a;">Report Details #${report.id}</h2>
        <button onclick="this.closest('.modal-overlay').remove()" style="background:none;border:none;font-size:24px;cursor:pointer;color:#666;">&times;</button>
      </div>
      
      <div style="background:#f8f9fa;padding:20px;border-radius:10px;margin-bottom:20px;">
        <div style="margin-bottom:15px;">
          <strong style="color:#666;font-size:14px;">Place:</strong>
          <div style="font-size:18px;font-weight:600;color:#1a1a1a;margin-top:5px;">${report.place_name || 'Unknown Place'}</div>
        </div>
        
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:15px;">
          <div>
            <strong style="color:#666;font-size:14px;">Issue Type:</strong>
            <div style="margin-top:5px;color:#1a1a1a;">${report.reason || 'N/A'}</div>
          </div>
          <div>
            <strong style="color:#666;font-size:14px;">Reported By:</strong>
            <div style="margin-top:5px;color:#1a1a1a;">${report.reported_by || 'Anonymous'}</div>
          </div>
        </div>
        
        <div style="margin-bottom:15px;">
          <strong style="color:#666;font-size:14px;">Date:</strong>
          <div style="margin-top:5px;color:#1a1a1a;">${report.created_at ? new Date(report.created_at).toLocaleString() : 'N/A'}</div>
        </div>
        
        <div style="margin-bottom:15px;">
          <strong style="color:#666;font-size:14px;">Status:</strong>
          <div style="margin-top:5px;">
            <span class="status-badge ${statusClass}" style="display:inline-block;padding:6px 12px;border-radius:20px;font-size:13px;font-weight:600;">${statusText}</span>
          </div>
        </div>
        
        <div>
          <strong style="color:#666;font-size:14px;">Message:</strong>
          <div style="margin-top:8px;padding:15px;background:white;border-radius:8px;color:#1a1a1a;line-height:1.6;">${report.message || 'No message provided'}</div>
        </div>
      </div>
      
      ${report.status === 'pending' ? `
        <div style="display:flex;gap:10px;justify-content:flex-end;">
          <button onclick="deleteReportedPlace(${report.place_id}, ${report.id})" style="padding:12px 24px;background:#f44336;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:8px;">
            <i class="fas fa-trash"></i> Delete Place
          </button>
          <button onclick="updateReportFromModal(${report.id}, 'resolved')" style="padding:12px 24px;background:#4CAF50;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:8px;">
            <i class="fas fa-check"></i> Resolve (Keep Place)
          </button>
          <button onclick="updateReportFromModal(${report.id}, 'rejected')" style="padding:12px 24px;background:#666;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:8px;">
            <i class="fas fa-times"></i> Reject Report
          </button>
        </div>
      ` : `
        <div style="text-align:center;color:#666;font-style:italic;">This report has been ${statusText.toLowerCase()}</div>
      `}
    </div>
  `;

  document.body.appendChild(modal);

  // Close on overlay click
  modal.addEventListener('click', e => {
    if (e.target === modal) modal.remove();
  });
}

async function updateReportFromModal(reportId, status) {
  // Close modal first
  document.querySelector('.modal-overlay')?.remove();

  // Update report
  await updateReport(reportId, status);
}

async function deleteReportedPlace(placeId, reportId) {
  if (!confirm('Are you sure you want to DELETE this place? This action cannot be undone!')) {
    return;
  }

  try {
    // Close modal
    document.querySelector('.modal-overlay')?.remove();

    // Delete the place
    await ADMIN_API.del('/admin/places/delete', { place_id: placeId });

    // Mark report as resolved
    await ADMIN_API.post('/admin/reports', { report_id: reportId, status: 'resolved' });

    showToast('Place deleted successfully!', 'success');
    await loadReports();
  } catch (err) {
    console.error('Error deleting place:', err);
    showToast('Failed to delete place', 'error');
  }
}

async function updateReport(reportId, status) {
  if (!confirm(`Mark report as ${status}?`)) return;
  try {
    await ADMIN_API.post('/admin/reports', { report_id: reportId, status });
    showToast(`Report ${status}!`, 'success');
    await loadReports();
  } catch (err) { showToast('Failed to update report', 'error'); }
}

function filterReports(filter) {
  const statusMap = { 'all': '', 'pending': 'pending', 'resolved': 'resolved', 'rejected': 'rejected' };
  loadReports(statusMap[filter.toLowerCase()] || '');
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
}

function setupEventListeners() {
  const search = document.getElementById('globalSearch');
  if (search) {
    search.addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#reportedTable tr').forEach(row => {
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

window.viewReport = viewReport;
window.updateReport = updateReport;
window.updateReportFromModal = updateReportFromModal;
window.deleteReportedPlace = deleteReportedPlace;
window.filterReports = filterReports;
