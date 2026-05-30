document.addEventListener("DOMContentLoaded", async function () {
  if (!initPage()) return;

  try {
    await loadDashboardData();

    // Wait for Leaflet to be ready before initializing map
    if (window.L) {
      if (window.initializeMaps) {
        window.initializeMaps();
      }
    } else {
      console.log("Waiting for Leaflet to load...");
      // Leaflet will be available after script loads
      setTimeout(() => {
        if (window.initializeMaps) {
          window.initializeMaps();
        }
      }, 500);
    }
  } catch (err) {
    console.error("Dashboard error:", err);
    showToast("Failed to load dashboard data", "error");
  }
});

async function loadDashboardData() {
  const [placesRes, reportsRes, usersRes] = await Promise.all([
    ADMIN_API.get("/admin/places"),
    ADMIN_API.get("/admin/reports"),
    ADMIN_API.get("/admin/users"),
  ]);

  const places = placesRes.places || [];
  const reports = reportsRes.data || [];
  const users = usersRes.users || [];

  updateStats(places, reports, users);
  updateBadges(places, reports);
  loadRecentActivities(places);
  loadRecentPlaces(places);
}

function updateStats(places, reports, users) {
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };
  set("totalPlaces", places.length);
  set("verifiedPlaces", places.filter((p) => p.status === "approved").length);
  set("pendingPlaces", places.filter((p) => p.status !== "approved").length);
  set("reportedPlaces", reports.filter((r) => r.status === "pending").length);
  set("totalUsers", users.length);
}

function updateBadges(places, reports) {
  const pb = document.getElementById("placesBadge");
  const rb = document.getElementById("reportedBadge");
  const placesCount = places.length;
  const reportsCount = reports.filter((r) => r.status === "pending").length;

  if (pb) {
    pb.textContent = placesCount;
    pb.style.display = placesCount > 0 ? "inline-block" : "none";
  }
  if (rb) {
    rb.textContent = reportsCount;
    rb.style.display = reportsCount > 0 ? "inline-block" : "none";
  }
}

function loadRecentActivities(places) {
  const list = document.getElementById("activityList");
  if (!list) return;
  const recent = places.slice(0, 5);
  if (!recent.length) return;
  list.innerHTML = recent
    .map(
      (p) => `
        <div class="activity-item">
            <div class="activity-icon"><i class="fas fa-map-marker-alt"></i></div>
            <div class="activity-content">
                <p>New place added: ${p.name || "Unnamed Place"}</p>
                <div class="activity-meta"><span>${p.created_at ? new Date(p.created_at).toLocaleDateString() : "Recently"}</span></div>
            </div>
        </div>`,
    )
    .join("");
}

function toRating(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  return Math.max(0, Math.min(5, num));
}

function loadRecentPlaces(places) {
  const tbody = document.getElementById("recentPlacesTable");
  if (!tbody) return;
  const recent = places.slice(0, 5);
  if (!recent.length) return;
  tbody.innerHTML = recent
    .map((p) => {
      const statusClass =
        p.status === "approved" ? "status-verified" : "status-pending";
      const statusText = p.status === "approved" ? "Approved" : "Pending";
      const avg = (
        (toRating(p.wifi_rating) +
          toRating(p.power_rating) +
          toRating(p.service_rating)) /
        3
      ).toFixed(1);
      return `<tr>
            <td><strong>${p.name || "Unnamed"}</strong></td>
            <td>${p.category || "N/A"}</td>
            <td>${avg}</td>
            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
            <td>${p.created_at ? new Date(p.created_at).toLocaleDateString() : "N/A"}</td>
        </tr>`;
    })
    .join("");
}

window.refreshData = async function () {
  showToast("Refreshing...", "info");
  try {
    await loadDashboardData();
    showToast("Refreshed!", "success");
  } catch {
    showToast("Failed to refresh", "error");
  }
};

function showToast(message, type = "info") {
  let c = document.getElementById("toastContainer");
  if (!c) {
    c = document.createElement("div");
    c.id = "toastContainer";
    document.body.appendChild(c);
  }
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.textContent = message;
  c.appendChild(t);
  setTimeout(() => {
    t.style.opacity = "0";
    setTimeout(() => t.remove(), 300);
  }, 3000);
}
