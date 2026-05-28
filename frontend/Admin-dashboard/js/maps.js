// maps.js - Leaflet Maps for Admin Dashboard

let mapsInitialized = false;
let dashboardMap = null;
let placesMap = null;
let reportedMap = null;
let mapMarkers = {
  dashboard: [],
  places: [],
  reported: [],
};

// Initialize Leaflet Maps
function initializeMaps() {
  if (!window.L) {
    console.error("Leaflet not loaded");
    showToast("Maps library failed to load", "error");
    return;
  }

  console.log('Initializing Leaflet maps...');

  try {
    // Initialize Dashboard Map
    if (document.getElementById("dashboardMap")) {
      console.log('Creating dashboard map...');
      dashboardMap = L.map('dashboardMap').setView([9.032, 38.757], 12);

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 19
      }).addTo(dashboardMap);

      console.log('Dashboard map created, loading places...');
      loadDashboardMap();
    }

    // Initialize Places Map
    if (document.getElementById("placesMap")) {
      console.log('Creating places map...');
      placesMap = L.map('placesMap').setView([9.032, 38.757], 12);

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 19
      }).addTo(placesMap);
    }

    // Initialize Reported Map
    if (document.getElementById("reportedMap")) {
      console.log('Creating reported map...');
      reportedMap = L.map('reportedMap').setView([9.032, 38.757], 12);

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 19
      }).addTo(reportedMap);
    }

    mapsInitialized = true;
    console.log("Leaflet maps initialized successfully");
  } catch (error) {
    console.error("Error initializing maps:", error);
    showToast("Failed to initialize maps", "error");
  }
}

// Load dashboard map with places
async function loadDashboardMap() {
  if (!dashboardMap) {
    console.error('Dashboard map not initialized');
    return;
  }

  try {
    // Clear existing markers
    mapMarkers.dashboard.forEach((marker) => dashboardMap.removeLayer(marker));
    mapMarkers.dashboard = [];

    // Load places from PHP API
    const res = await ADMIN_API.get('/admin/places');
    const places = (res.places || []).map(p => ({
      ...p,
      location: p.location ? (() => {
        const parts = p.location.split(',');
        return parts.length === 2 ? { _lat: parseFloat(parts[0]), _long: parseFloat(parts[1]) } : null;
      })() : null
    }));

    // Add places to map
    places.forEach((place) => {
      if (place.location && place.location._lat && place.location._long) {
        const markerColor = place.status === "approved" ? "green" : "orange";

        // Create custom icon
        const icon = L.divIcon({
          className: 'custom-marker',
          html: `<div style="background-color: ${markerColor}; width: 25px; height: 25px; border-radius: 50%; border: 3px solid white; box-shadow: 0 2px 5px rgba(0,0,0,0.3);"></div>`,
          iconSize: [25, 25],
          iconAnchor: [12, 12]
        });

        const marker = L.marker([place.location._lat, place.location._long], { icon })
          .addTo(dashboardMap)
          .bindPopup(createPlaceInfoWindow(place));

        mapMarkers.dashboard.push(marker);
      }
    });

    // Adjust map bounds to show all markers
    if (places.length > 0 && mapMarkers.dashboard.length > 0) {
      const group = L.featureGroup(mapMarkers.dashboard);
      dashboardMap.fitBounds(group.getBounds().pad(0.1));
    }

    console.log(`Loaded ${mapMarkers.dashboard.length} markers on dashboard map`);
  } catch (error) {
    console.error("Error loading dashboard map:", error);
    showToast("Failed to load map data", "error");
  }
}

// Load places map with filtering
async function loadPlacesMap(filter = "all") {
  console.log("loadPlacesMap called with filter:", filter);

  if (!placesMap) {
    console.error("placesMap is not initialized!");
    return;
  }

  try {
    // Clear existing markers
    mapMarkers.places.forEach((marker) => placesMap.removeLayer(marker));
    mapMarkers.places = [];

    // Load places from PHP API
    const res = await ADMIN_API.get('/admin/places');
    let places = (res.places || []).map(p => ({
      ...p,
      location: p.location ? (() => {
        const parts = p.location.split(',');
        return parts.length === 2 ? { _lat: parseFloat(parts[0]), _long: parseFloat(parts[1]) } : null;
      })() : null
    }));

    // Apply filter - fix: 'verified' should filter for 'approved' status
    if (filter === "approved" || filter === "verified") {
      places = places.filter((p) => p.status === "approved");
    } else if (filter === "pending") {
      places = places.filter((p) => p.status === "pending");
    }

    places.forEach((place) => {
      if (place.location && place.location._lat && place.location._long) {
        const markerColor = place.status === "approved" ? "green" : "orange";

        const icon = L.divIcon({
          className: 'custom-marker',
          html: `<div style="background-color: ${markerColor}; width: 25px; height: 25px; border-radius: 50%; border: 3px solid white; box-shadow: 0 2px 5px rgba(0,0,0,0.3);"></div>`,
          iconSize: [25, 25],
          iconAnchor: [12, 12]
        });

        const marker = L.marker([place.location._lat, place.location._long], { icon })
          .addTo(placesMap)
          .bindPopup(createPlaceInfoWindow(place));

        mapMarkers.places.push(marker);
      }
    });

    // Adjust map bounds
    if (places.length > 0 && mapMarkers.places.length > 0) {
      const group = L.featureGroup(mapMarkers.places);
      placesMap.fitBounds(group.getBounds().pad(0.1));
    } else {
      placesMap.setView([9.032, 38.757], 12);
    }

    console.log(`Loaded ${mapMarkers.places.length} markers on places map (filter: ${filter})`);
  } catch (error) {
    console.error("Error loading places map:", error);
    showToast("Failed to load places map", "error");
  }
}

// Load reported map
async function loadReportedMap(filter = "all") {
  if (!reportedMap) return;

  try {
    // Clear existing markers
    mapMarkers.reported.forEach((marker) => reportedMap.removeLayer(marker));
    mapMarkers.reported = [];

    // Load reports from PHP API
    const res = await ADMIN_API.get('/admin/reports');
    let reports = (res.data || []).map(r => ({
      ...r,
      location: r.location ? (() => {
        const parts = r.location.split(',');
        return parts.length === 2 ? { _lat: parseFloat(parts[0]), _long: parseFloat(parts[1]) } : null;
      })() : null
    }));

    // Apply filter
    if (filter === "pending") {
      reports = reports.filter((r) => r.status === "pending");
    } else if (filter === "resolved") {
      reports = reports.filter((r) => r.status === "resolved");
    }

    reports.forEach((report) => {
      if (report.location && report.location._lat && report.location._long) {
        const markerColor = report.status === "pending" ? "red" : "green";

        const icon = L.divIcon({
          className: 'custom-marker',
          html: `<div style="background-color: ${markerColor}; width: 25px; height: 25px; border-radius: 50%; border: 3px solid white; box-shadow: 0 2px 5px rgba(0,0,0,0.3);"></div>`,
          iconSize: [25, 25],
          iconAnchor: [12, 12]
        });

        const marker = L.marker([report.location._lat, report.location._long], { icon })
          .addTo(reportedMap)
          .bindPopup(createReportInfoWindow(report));

        mapMarkers.reported.push(marker);
      }
    });

    // Adjust map bounds
    if (reports.length > 0 && mapMarkers.reported.length > 0) {
      const group = L.featureGroup(mapMarkers.reported);
      reportedMap.fitBounds(group.getBounds().pad(0.1));
    }

    console.log(`Loaded ${mapMarkers.reported.length} markers on reported map`);
  } catch (error) {
    console.error("Error loading reported map:", error);
    showToast("Failed to load reported issues map", "error");
  }
}

// Create place info window content
function createPlaceInfoWindow(place) {
  const stars = getStarRating(place.rating?.overall || 0);
  const statusText = place.status === "approved" ? "Approved" : "Pending";

  // Get image URL - priority: image_url (Supabase) > image_data (base64) > image (legacy) > placeholder
  let imageUrl = "https://via.placeholder.com/100";
  if (place.image_url) {
    imageUrl = place.image_url;
  } else if (place.image_data && place.image_mime) {
    imageUrl = `data:${place.image_mime};base64,${place.image_data}`;
  } else if (place.image) {
    // Legacy file path
    imageUrl = `http://localhost:8000/${place.image}`;
  }

  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 250px;">
      <div style="display: flex; align-items: center; margin-bottom: 10px; gap: 8px;">
        <img src="${imageUrl}" alt="${place.name}" style="width: 50px; height: 50px; object-fit: cover; border-radius: 6px;">
        <div>
          <div style="font-weight: 600; font-size: 14px; color: #1a1a1a; margin-bottom: 3px;">${place.name}</div>
          <div style="display: flex; align-items: center; gap: 3px; margin-bottom: 3px;">
            ${stars}
          </div>
          <span style="background: ${place.status === "approved" ? "#4CAF50" : "#FF9800"}; color: white; padding: 2px 6px; border-radius: 10px; font-size: 11px; font-weight: 500;">
            ${statusText}
          </span>
        </div>
      </div>
      <div style="margin-bottom: 8px; font-size: 13px;">
        <p style="margin: 3px 0;"><strong>Category:</strong> ${place.category || "N/A"}</p>
        <p style="margin: 3px 0;"><strong>WiFi:</strong> ${place.wifi_rating || "N/A"}/5</p>
        <p style="margin: 3px 0;"><strong>Power:</strong> ${place.power_rating || "N/A"}/5</p>
      </div>
    </div>
  `;
}

// Create report info window content
function createReportInfoWindow(report) {
  const statusText = report.status === "pending" ? "Pending Review" : "Resolved";

  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 250px;">
      <div style="display: flex; align-items: center; margin-bottom: 10px; gap: 8px;">
        <div style="width: 40px; height: 40px; background: #f44336; border-radius: 6px; display: flex; align-items: center; justify-content: center;">
          <i class="fas fa-flag" style="color: white; font-size: 16px;"></i>
        </div>
        <div>
          <div style="font-weight: 600; font-size: 14px; color: #1a1a1a; margin-bottom: 3px;">${report.placeName || "Reported Issue"}</div>
          <span style="background: ${report.status === "pending" ? "#f44336" : "#4CAF50"}; color: white; padding: 2px 6px; border-radius: 10px; font-size: 11px; font-weight: 500;">
            ${statusText}
          </span>
        </div>
      </div>
      <div style="font-size: 13px;">
        <p style="margin: 3px 0;"><strong>Reason:</strong> ${report.reason || "N/A"}</p>
        <p style="margin: 3px 0;"><strong>Reported By:</strong> ${report.reportedBy || "Anonymous"}</p>
      </div>
    </div>
  `;
}

// Map layer toggles
function toggleMapLayer(layer) {
  if (!dashboardMap) return;

  // Show/hide markers based on layer
  mapMarkers.dashboard.forEach((marker) => {
    // This is a simplified version - you can enhance it based on marker properties
    dashboardMap.addLayer(marker);
  });
}

function togglePlacesMapLayer(layer) {
  console.log("togglePlacesMapLayer called with:", layer);

  // Update active state on map toggle buttons
  document.querySelectorAll('.map-toggle').forEach(btn => btn.classList.remove('active'));
  event?.target?.closest('.map-toggle')?.classList.add('active');

  loadPlacesMap(layer);
}

function toggleReportedMapLayer(layer) {
  loadReportedMap(layer);
}

// Helper function to get star rating HTML
function getStarRating(rating) {
  const fullStars = Math.floor(rating);
  const halfStar = rating % 1 >= 0.5;
  const emptyStars = 5 - fullStars - (halfStar ? 1 : 0);

  let stars = "";
  for (let i = 0; i < fullStars; i++) {
    stars += '<i class="fas fa-star" style="color: #FFD700; font-size: 11px;"></i>';
  }
  if (halfStar) {
    stars += '<i class="fas fa-star-half-alt" style="color: #FFD700; font-size: 11px;"></i>';
  }
  for (let i = 0; i < emptyStars; i++) {
    stars += '<i class="far fa-star" style="color: #FFD700; font-size: 11px;"></i>';
  }
  return stars;
}

// Helper function to show toast notifications
function showToast(message, type = "info") {
  let toastContainer = document.getElementById("toast-container");
  if (!toastContainer) {
    toastContainer = document.createElement("div");
    toastContainer.id = "toast-container";
    toastContainer.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 10000;
    `;
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.style.cssText = `
    background: ${type === "success" ? "#4CAF50" : type === "error" ? "#f44336" : "#2196F3"};
    color: white;
    padding: 15px 20px;
    border-radius: 8px;
    margin-bottom: 10px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    animation: slideIn 0.3s ease-out;
  `;

  toast.textContent = message;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = "slideOut 0.3s ease-out";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Export for use in other files
window.mapsModule = {
  initializeMaps,
  loadDashboardMap,
  loadPlacesMap,
  loadReportedMap,
  toggleMapLayer,
  togglePlacesMapLayer,
  toggleReportedMapLayer,
};

// Make functions available globally for onclick handlers
window.initializeMaps = initializeMaps;
window.loadDashboardMap = loadDashboardMap;
window.loadPlacesMap = loadPlacesMap;
window.loadReportedMap = loadReportedMap;
window.toggleMapLayer = toggleMapLayer;
window.togglePlacesMapLayer = togglePlacesMapLayer;
window.toggleReportedMapLayer = toggleReportedMapLayer;
