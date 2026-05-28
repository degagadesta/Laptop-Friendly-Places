// Admin add place with Leaflet map

let map = null;
let marker = null;
let selectedCoordinates = null;

document.addEventListener("DOMContentLoaded", function () {
  console.log("Add Place page loaded - using Leaflet");

  if (!initPage()) return;

  initializeMap();
  setupEventListeners();
});

function initializeMap() {
  console.log("Initializing Leaflet map...");

  const mapContainer = document.getElementById("mapContainer");
  if (!mapContainer) {
    console.error("Map container not found");
    return;
  }

  if (!window.L) {
    console.error("Leaflet not loaded");
    showToast("Map library not loaded. Please refresh the page.", "error");
    return;
  }

  map = L.map("mapContainer").setView([9.032, 38.757], 12);

  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap contributors",
    maxZoom: 19,
  }).addTo(map);

  map.on("click", function (e) {
    setLocation(e.latlng.lat, e.latlng.lng);
  });

  console.log("Leaflet map initialized successfully");
}

function setLocation(lat, lng) {
  if (marker) {
    map.removeLayer(marker);
  }

  marker = L.marker([lat, lng]).addTo(map);
  selectedCoordinates = { lat, lng };

  document.getElementById("latitude").value = lat;
  document.getElementById("longitude").value = lng;

  const locationInfo = document.getElementById("selectedLocationInfo");
  const coordinatesDisplay = document.getElementById("selectedCoordinates");

  if (locationInfo && coordinatesDisplay) {
    coordinatesDisplay.textContent = lat.toFixed(6) + ", " + lng.toFixed(6);
    locationInfo.style.display = "block";
  }

  showToast("Location selected on map", "success");
}

function setupEventListeners() {
  const addPlaceForm = document.getElementById("addPlaceForm");
  if (addPlaceForm) {
    addPlaceForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      await handleAddPlace();
    });
  }

  const imageInput = document.getElementById("imageFiles");
  if (imageInput) {
    imageInput.addEventListener("change", updateImagePreview);
  }

  const videoInput = document.getElementById("videoFile");
  if (videoInput) {
    videoInput.addEventListener("change", updateVideoPreview);
  }
}

async function handleAddPlace() {
  const lat = parseFloat(document.getElementById("latitude").value);
  const lng = parseFloat(document.getElementById("longitude").value);

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    showToast("Please select a location on the map first", "error");
    return;
  }

  const name = document.getElementById("placeName").value.trim();
  const category = document.getElementById("placeCategory").value;
  const description = document.getElementById("description").value.trim();
  const wifiRating = clampRating(
    parseInt(document.getElementById("wifiRating").value) || 3,
  );
  const powerRating = clampRating(
    parseInt(document.getElementById("powerRating").value) || 3,
  );
  const serviceRating = clampRating(
    parseInt(document.getElementById("serviceRating").value) || 3,
  );

  if (!name) {
    showToast("Please enter a place name", "error");
    return;
  }

  if (!category) {
    showToast("Please select a place category", "error");
    return;
  }

  const imageInput = document.getElementById("imageFiles");
  const imageFiles = Array.from(imageInput?.files || []);

  if (imageFiles.length < 1 || imageFiles.length > 3) {
    showToast("Please upload between 1 and 3 images", "error");
    return;
  }

  const allowedImageTypes = [
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/gif",
    "image/webp",
  ];
  for (const file of imageFiles) {
    if (!allowedImageTypes.includes(file.type)) {
      showToast("Please upload only JPEG, PNG, GIF, or WebP images", "error");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      showToast("Each image must be 5MB or less", "error");
      return;
    }
  }

  const images = [];
  for (const file of imageFiles) {
    const data = await compressAndEncode(file, 1200, 0.8);
    images.push({ data, mime: "image/jpeg" });
  }

  let videoData = null;
  let videoMime = null;
  const videoInput = document.getElementById("videoFile");
  const videoFile = videoInput?.files?.[0] || null;

  if (videoFile) {
    if (videoFile.size > 50 * 1024 * 1024) {
      showToast("Video file size should be less than 50MB", "error");
      return;
    }
    videoMime = videoFile.type || "video/mp4";
    videoData = await fileToBase64(videoFile);
  }

  const submitBtn = document.querySelector(
    '#addPlaceForm button[type="submit"]',
  );
  const originalBtnHtml = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';
  }

  const placeData = {
    name,
    description: description || `A ${category} in Addis Ababa`,
    category,
    location: `${lat},${lng}`,
    wifi_rating: wifiRating,
    power_rating: powerRating,
    service_rating: serviceRating,
    images,
    video_data: videoData,
    video_mime: videoMime,
  };

  try {
    console.log("Adding place via PHP API:", {
      ...placeData,
      images: `[${images.length} image(s)]`,
      video_data: videoData ? "[video attached]" : null,
    });

    const createRes = await ADMIN_API.post("/places/contribute", placeData);

    if (createRes.place_id) {
      await ADMIN_API.post("/admin/places/approve", {
        place_id: createRes.place_id,
      });
    }

    showToast(`Place "${name}" added successfully!`, "success");
    resetForm();

    setTimeout(function () {
      window.location.href = "places.html";
    }, 1500);
  } catch (error) {
    console.error("Error adding place:", error);
    showToast("Failed to add place: " + error.message, "error");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnHtml;
    }
  }
}

function updateImagePreview() {
  const preview = document.getElementById("imagePreview");
  const input = document.getElementById("imageFiles");
  if (!preview || !input) return;

  preview.innerHTML = "";
  const files = Array.from(input.files || []);

  files.slice(0, 3).forEach((file) => {
    const img = document.createElement("img");
    img.src = URL.createObjectURL(file);
    img.alt = file.name;
    img.style.cssText =
      "width:80px;height:80px;object-fit:cover;border-radius:8px;border:1px solid #ddd;";
    preview.appendChild(img);
  });
}

function updateVideoPreview() {
  const preview = document.getElementById("videoPreview");
  const input = document.getElementById("videoFile");
  if (!preview || !input) return;

  preview.innerHTML = "";
  const file = input.files?.[0];
  if (!file) return;

  const video = document.createElement("video");
  video.src = URL.createObjectURL(file);
  video.controls = true;
  video.style.cssText =
    "width:180px;max-width:100%;border-radius:8px;border:1px solid #ddd;";
  preview.appendChild(video);
}

function clampRating(value) {
  return Math.max(0, Math.min(5, Number.isFinite(value) ? value : 0));
}

function resetForm() {
  const form = document.getElementById("addPlaceForm");
  if (form) {
    form.reset();
  }

  document.getElementById("latitude").value = "";
  document.getElementById("longitude").value = "";

  const locationInfo = document.getElementById("selectedLocationInfo");
  if (locationInfo) {
    locationInfo.style.display = "none";
  }

  const imagePreview = document.getElementById("imagePreview");
  if (imagePreview) imagePreview.innerHTML = "";
  const videoPreview = document.getElementById("videoPreview");
  if (videoPreview) videoPreview.innerHTML = "";

  if (marker && map) {
    map.removeLayer(marker);
    marker = null;
  }

  selectedCoordinates = null;
  showToast("Form reset", "info");
}

function showToast(message, type = "info") {
  console.log(`Toast (${type}): ${message}`);

  let bgColor = "#2196F3";
  if (type === "success") bgColor = "#4CAF50";
  if (type === "error") bgColor = "#f44336";

  const toast = document.createElement("div");
  toast.className = "toast toast-" + type;
  toast.textContent = message;
  toast.style.cssText = `position: fixed; top: 20px; right: 20px; background: ${bgColor}; color: white; padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10000; animation: slideIn 0.3s ease-out;`;

  const container = document.getElementById("toastContainer") || document.body;
  container.appendChild(toast);

  setTimeout(function () {
    toast.style.animation = "slideOut 0.3s ease-out";
    setTimeout(function () {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 300);
  }, 3000);
}

function compressAndEncode(file, maxWidth = 1200, quality = 0.8) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = reject;
    reader.onload = (e) => {
      const img = new Image();
      img.onerror = reject;
      img.onload = () => {
        const canvas = document.createElement("canvas");
        let w = img.width;
        let h = img.height;
        if (w > maxWidth) {
          h = Math.round((h * maxWidth) / w);
          w = maxWidth;
        }
        canvas.width = w;
        canvas.height = h;
        canvas.getContext("2d").drawImage(img, 0, 0, w, h);
        resolve(canvas.toDataURL("image/jpeg", quality));
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  });
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = reject;
    reader.onload = (e) => resolve(e.target.result);
    reader.readAsDataURL(file);
  });
}

window.resetForm = resetForm;
