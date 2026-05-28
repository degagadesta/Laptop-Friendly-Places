import { placesAPI } from "./placesAPI.js";
import { auth } from "./auth.js";
import { STORAGE_KEYS } from "./apiConfig.js";

// Check for email verification success and auto-login
document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const verified = urlParams.get("verified");
  const token = urlParams.get("token");
  const userJson = urlParams.get("user");

  if (verified === "success" && token && userJson) {
    try {
      const user = JSON.parse(decodeURIComponent(userJson));

      // Store auth data
      localStorage.setItem(STORAGE_KEYS.TOKEN, token);
      localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));

      // Update auth object
      auth.token = token;
      auth.user = user;

      // Show success message
      showWelcomeMessage(user.name);

      // Clean URL
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (e) {
      console.error("Error processing verification:", e);
    }
  } else if (verified === "already") {
    alert("Your email is already verified. Please login.");
    window.location.href = "login.html";
  }
});

function showWelcomeMessage(name) {
  const message = document.createElement("div");
  message.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 20px 30px;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;
  message.innerHTML = `
        <div style="display:flex;align-items:center;gap:12px;">
            <i class="fas fa-check-circle" style="font-size:24px;"></i>
            <div>
                <div style="font-weight:600;font-size:16px;">Email Verified!</div>
                <div style="font-size:14px;opacity:0.9;">Welcome, ${name}! You're now logged in.</div>
            </div>
        </div>
    `;
  document.body.appendChild(message);

  setTimeout(() => {
    message.style.animation = "slideOut 0.3s ease-out";
    setTimeout(() => message.remove(), 300);
  }, 5000);
}

// Helper: build image src from place data
function getImageSrc(place) {
  // Priority: image_url (Supabase) > image_data (base64) > image (legacy path)
  if (place.image_url) {
    return place.image_url;
  }
  if (place.image_data && place.image_mime) {
    return `data:${place.image_mime};base64,${place.image_data}`;
  }
  if (place.image) {
    return `http://localhost:8000/${place.image}`;
  }
  return null;
}

// Initialize the home map
const homeMap = L.map("homeMap", {
  center: [9.03, 38.74],
  zoom: 13,
  zoomControl: false,
  dragging: false,
  scrollWheelZoom: false,
  doubleClickZoom: false,
  boxZoom: false,
  keyboard: false,
  tap: false,
});

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  attribution: "&copy; OpenStreetMap contributors",
}).addTo(homeMap);

async function loadPlacesOnMap() {
  try {
    const places = await placesAPI.getAllPlaces();

    // Update stat cards
    const total = places.length;
    const recent = places.filter((p) => {
      if (!p.created_at) return false;
      return (
        new Date(p.created_at) >= new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
      );
    }).length;
    const contributors = new Set(
      places.map((p) => p.created_by).filter(Boolean),
    ).size;

    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };
    set("totalPlaces", total);
    set("newAdded", recent);
    set("totalContributors", contributors);
    set("sidebarTotalPlaces", total);

    const cafes = places.filter((p) => {
      const category = (p.category || "").toLowerCase().trim();
      return (
        category === "cafe" ||
        /cafe|coffee|café/i.test((p.name || "") + " " + (p.description || ""))
      );
    }).length;
    const hotels = places.filter((p) => {
      const category = (p.category || "").toLowerCase().trim();
      return (
        category === "hotel" ||
        /hotel|lodge|inn/i.test((p.name || "") + " " + (p.description || ""))
      );
    }).length;
    set("cafeCount", cafes);
    set("hotelCount", hotels);

    places.forEach((place) => {
      if (!place.location) return;
      const parts = place.location.split(",");
      if (parts.length < 2) return;
      const lat = parseFloat(parts[0].trim());
      const lng = parseFloat(parts[1].trim());
      if (isNaN(lat) || isNaN(lng)) return;

      const marker = L.marker([lat, lng]).addTo(homeMap);
      marker.bindPopup(`
                <div class="place-popup">
                    <h3>${place.name || "Unnamed Place"}</h3>
                    <p>${place.description || "No description"}</p>
                    <div class="ratings">
                        <span>WiFi: ${place.wifi_rating || "N/A"}/5</span><br>
                        <span>Power: ${place.power_rating || "N/A"}/5</span><br>
                        <span>Service: ${place.service_rating || "N/A"}/5</span>
                    </div>
                    <a href="places.html?id=${place.id}">View Details</a>
                </div>
            `);
    });
  } catch (error) {
    console.error("Error loading places:", error);
    [
      "totalPlaces",
      "newAdded",
      "totalContributors",
      "sidebarTotalPlaces",
      "cafeCount",
      "hotelCount",
    ].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.textContent = "—";
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadPlacesOnMap();
});

document.getElementById("profile")?.addEventListener("click", () => {
  window.location.href = "profile.html";
});
document.getElementById("headerProfile")?.addEventListener("click", () => {
  window.location.href = "profile.html";
});
