import { auth, requireAuth } from "./auth.js";
import { API_CONFIG } from "./apiConfig.js";

if (!requireAuth()) {
  /* requireAuth redirects */
}

const BASE = API_CONFIG.BASE_URL;

async function apiFetch(path, options = {}) {
  const res = await fetch(BASE + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${auth.token}`,
      ...(options.headers || {}),
    },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function clampRating(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return null;
  return Math.max(0, Math.min(5, num));
}

function formatRating(value) {
  const clamped = clampRating(value);
  return clamped === null ? "N/A" : clamped.toFixed(1);
}

function averageRating(place) {
  const ratings = [place.wifi_rating, place.power_rating, place.service_rating]
    .map(clampRating)
    .filter((v) => v !== null);

  if (!ratings.length) return "N/A";
  const avg = ratings.reduce((sum, value) => sum + value, 0) / ratings.length;
  return avg.toFixed(1);
}

async function getFavorites() {
  const data = await apiFetch("/favorites", { method: "GET" });
  return Array.isArray(data) ? data : [];
}

async function removeFavorite(placeId) {
  await apiFetch("/favorites", {
    method: "DELETE",
    body: JSON.stringify({ place_id: placeId }),
  });
  await renderFavorites();
}

function createFavoriteCard(place) {
  const card = document.createElement("div");
  card.className = "favorite-card";
  card.dataset.placeId = place.place_id || place.id;

  const imgSrc = getImageSrc(place);

  card.innerHTML = `
        <div class="fav-card-image" style="${imgSrc ? `background-image: url('${imgSrc}');` : ""}">
            ${!imgSrc ? '<div class="no-image"><i class="fa-solid fa-image"></i></div>' : ""}
            <div class="fav-badge"><i class="fa-solid fa-heart"></i> Favorite</div>
        </div>
        <div class="fav-card-content">
            <div class="fav-card-header">
                <h3>${place.name || "Place #" + (place.place_id || place.id)}</h3>
                <button class="fav-remove-btn" title="Remove from favorites">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <div class="fav-features">
                <span class="feature"><i class="fa-solid fa-wifi"></i> WiFi: ${formatRating(place.wifi_rating)}</span>
                <span class="feature"><i class="fa-solid fa-plug"></i> Power: ${formatRating(place.power_rating)}</span>
                <span class="feature"><i class="fa-solid fa-face-smile"></i> Service: ${formatRating(place.service_rating)}</span>
            </div>
        </div>`;

  card.querySelector(".fav-remove-btn").addEventListener("click", (e) => {
    e.stopPropagation();
    removeFavorite(place.place_id || place.id);
  });

  card.addEventListener("click", () => openPlaceSheet(place));
  return card;
}

function getImageSrc(place) {
  if (place.image_url) {
    return place.image_url;
  }
  if (place.image_data && place.image_mime) {
    return `data:${place.image_mime};base64,${place.image_data}`;
  }
  if (place.image) {
    if (place.image.startsWith("http")) {
      return place.image;
    }
    return `http://localhost:8000/${place.image}`;
  }
  return null;
}

async function renderFavorites() {
  const grid = document.querySelector(".favorites-grid");
  const emptyState = document.getElementById("emptyState");

  try {
    const favorites = await getFavorites();

    if (!favorites.length) {
      grid.style.display = "none";
      emptyState.style.display = "block";
    } else {
      grid.style.display = "grid";
      emptyState.style.display = "none";
      grid.innerHTML = "";
      favorites.forEach((place) => grid.appendChild(createFavoriteCard(place)));
    }
  } catch (err) {
    console.error("Error loading favorites:", err);
    grid.innerHTML = "<p>Failed to load favorites.</p>";
  }
}

function openPlaceSheet(place) {
  const sheet = document.getElementById("placeSheet");
  const overlay = document.getElementById("sheetOverlay");

  document.getElementById("sheetName").textContent = place.name || "Place";
  document.getElementById("sheetDescription").textContent =
    place.description || "No description";
  document.getElementById("sheetRating").textContent = averageRating(place);
  document.getElementById("sheetWifi").textContent = formatRating(
    place.wifi_rating,
  );
  document.getElementById("sheetPower").textContent = formatRating(
    place.power_rating,
  );
  document.getElementById("sheetService").textContent = formatRating(
    place.service_rating,
  );

  const carousel = document.getElementById("mediaCarousel");
  const imgSrc = getImageSrc(place);
  carousel.innerHTML = imgSrc
    ? `<img src="${imgSrc}" alt="${place.name || "Place image"}" class="active">`
    : '<div class="no-media"><i class="fa-solid fa-image"></i><p>No images available</p></div>';
  currentSlide = 0;

  sheet.dataset.placeId = place.place_id || place.id || "";
  sheet.dataset.placeName = place.name || "";
  sheet.dataset.lat = place.lat || "";
  sheet.dataset.lng = place.lng || "";

  sheet.classList.add("active");
  overlay.classList.add("active");
}

function closePlaceSheet() {
  document.getElementById("placeSheet").classList.remove("active");
  document.getElementById("sheetOverlay").classList.remove("active");
}

renderFavorites();

document
  .getElementById("closeSheet")
  .addEventListener("click", closePlaceSheet);
document
  .getElementById("sheetOverlay")
  .addEventListener("click", closePlaceSheet);

document.getElementById("viewMapBtn").addEventListener("click", () => {
  const sheet = document.getElementById("placeSheet");
  const { lat, lng, placeId } = sheet.dataset;
  if (lat && lng)
    window.location.href = `map-view.html?lat=${lat}&lng=${lng}&placeId=${placeId}`;
  else alert("Location data not available");
});

document.getElementById("reportBtn").addEventListener("click", () => {
  const sheet = document.getElementById("placeSheet");
  const modal = document.getElementById("reportModal");
  modal.dataset.placeId = sheet.dataset.placeId;
  modal.dataset.placeName = sheet.dataset.placeName;
  closePlaceSheet();
  modal.classList.remove("hidden");
});

document.getElementById("profile").addEventListener("click", () => {
  window.location.href = "profile.html";
});
const hp = document.getElementById("headerProfile");
if (hp)
  hp.addEventListener("click", () => {
    window.location.href = "profile.html";
  });

document.getElementById("reportForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const modal = document.getElementById("reportModal");
  const placeId = modal.dataset.placeId;
  const issueType = document.getElementById("issueType").value;
  const desc = document.getElementById("desc").value;

  try {
    await apiFetch("/reports", {
      method: "POST",
      body: JSON.stringify({
        place_id: placeId,
        reason: issueType,
        message: desc,
      }),
    });
    alert("Report submitted successfully!");
    document.getElementById("reportForm").reset();
  } catch (err) {
    alert("Failed to submit report: " + err.message);
  }
  modal.classList.add("hidden");
});

document.getElementById("closeModal").addEventListener("click", () => {
  document.getElementById("reportModal").classList.add("hidden");
});

let currentSlide = 0;
function showSlide(index) {
  const items = document.querySelectorAll(
    "#mediaCarousel img, #mediaCarousel video",
  );
  if (!items.length) return;
  items.forEach((i) => {
    if (i.tagName === "VIDEO") {
      i.pause();
      i.currentTime = 0;
    }
  });
  currentSlide = (index + items.length) % items.length;
  items.forEach((i, idx) => i.classList.toggle("active", idx === currentSlide));
}
document
  .getElementById("prevBtn")
  .addEventListener("click", () => showSlide(currentSlide - 1));
document
  .getElementById("nextBtn")
  .addEventListener("click", () => showSlide(currentSlide + 1));
