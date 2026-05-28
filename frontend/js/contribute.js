import { requireAuth } from './auth.js';
import { placesAPI } from './placesAPI.js';

if (!requireAuth()) { /* requireAuth redirects */ }

document.addEventListener("DOMContentLoaded", () => {
  /* -------------------- MAP -------------------- */
  const map = L.map("map").setView([9.03, 38.74], 13);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors"
  }).addTo(map);
  setTimeout(() => map.invalidateSize(), 300);

  let marker;
  map.on("click", e => {
    document.getElementById("lat").value = e.latlng.lat;
    document.getElementById("lng").value = e.latlng.lng;
    if (marker) map.removeLayer(marker);
    marker = L.marker(e.latlng).addTo(map);
  });

  /* -------------------- STAR RATING -------------------- */
  const ratingInput = document.getElementById("overallRating");
  document.querySelectorAll(".rating-stars .star").forEach(star => {
    star.onclick = () => {
      const val = Number(star.dataset.value);
      ratingInput.value = val;
      document.querySelectorAll(".rating-stars .star").forEach(s =>
        s.classList.toggle("active", Number(s.dataset.value) <= val)
      );
    };
  });

  /* -------------------- PHOTO UPLOAD PREVIEW -------------------- */
  const photoUploadArea = document.getElementById("photoUploadArea");
  const photoInput = document.getElementById("photoInput");
  if (photoUploadArea && photoInput) {
    photoUploadArea.addEventListener("click", () => photoInput.click());
    photoInput.addEventListener("change", () => {
      const preview = document.getElementById("imagePreview");
      preview.innerHTML = '';
      Array.from(photoInput.files).slice(0, 3).forEach(file => {
        const img = document.createElement("img");
        img.style.cssText = "width:80px;height:80px;object-fit:cover;border-radius:8px;margin:4px;";
        img.src = URL.createObjectURL(file);
        preview.appendChild(img);
      });
    });
  }

  /* -------------------- VIDEO UPLOAD PREVIEW -------------------- */
  const videoUploadArea = document.getElementById("videoUploadArea");
  const videoInput = document.getElementById("videoInput");
  if (videoUploadArea && videoInput) {
    videoUploadArea.addEventListener("click", () => videoInput.click());
    videoInput.addEventListener("change", () => {
      const preview = document.getElementById("videoPreview");
      preview.innerHTML = '';
      if (videoInput.files.length > 0) {
        const file = videoInput.files[0];
        const video = document.createElement("video");
        video.style.cssText = "width:160px;height:90px;object-fit:cover;border-radius:8px;margin:4px;";
        video.src = URL.createObjectURL(file);
        video.controls = true;
        preview.appendChild(video);
      }
    });
  }

  /* -------------------- FORM SUBMIT -------------------- */
  document.getElementById("contributeForm").onsubmit = async e => {
    e.preventDefault();

    const lat = document.getElementById("lat").value;
    const lng = document.getElementById("lng").value;
    if (!lat || !lng) { alert("Please select a location on the map"); return; }
    if (!ratingInput.value) { alert("Please select an overall rating"); return; }

    const submitBtn = e.target.querySelector('.submit-btn');
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';
    submitBtn.disabled = true;

    try {
      const ratingMap = { 'Excellent': 5, 'Good': 4, 'Average': 3, 'Poor': 2, 'Very Poor': 1, 'Limited': 2, 'None': 1 };
      const wifi = ratingMap[document.getElementById("wifi").value] || 3;
      const power = ratingMap[document.getElementById("power").value] || 3;
      const service = ratingMap[document.getElementById("service").value] || 3;

      // Convert and compress image to base64 if provided
      let imageData = null;
      if (photoInput && photoInput.files.length > 0) {
        const file = photoInput.files[0];
        imageData = await compressAndEncode(file, 800, 0.7); // max 800px, 70% quality
      }

      // Convert video to base64 if provided
      let videoData = null;
      let videoMime = null;
      const videoInputEl = document.getElementById("videoInput");
      if (videoInputEl && videoInputEl.files.length > 0) {
        const videoFile = videoInputEl.files[0];

        // Check video size (max 50MB)
        if (videoFile.size > 50 * 1024 * 1024) {
          alert("Video file is too large. Maximum size is 50MB.");
          submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Place';
          submitBtn.disabled = false;
          return;
        }

        videoMime = videoFile.type;
        videoData = await fileToBase64(videoFile);
      }

      await placesAPI.contributePlace({
        name: document.getElementById("placeName").value,
        description: document.getElementById("description").value,
        location: `${lat},${lng}`,
        wifi_rating: wifi,
        power_rating: power,
        service_rating: service,
        image_data: imageData,
        video_data: videoData,
        video_mime: videoMime,
      });

      alert("✅ Place submitted successfully!");
      e.target.reset();
      if (marker) map.removeLayer(marker);
      document.querySelectorAll(".rating-stars .star").forEach(s => s.classList.remove("active"));
      document.getElementById("imagePreview").innerHTML = '';
      document.getElementById("videoPreview").innerHTML = '';
      setTimeout(() => { window.location.href = "home.html"; }, 1500);

    } catch (error) {
      console.error("Error submitting place:", error);
      alert("Failed to submit place: " + error.message);
    } finally {
      submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Place';
      submitBtn.disabled = false;
    }
  };

  /* -------------------- HELPERS -------------------- */
  // Compress image using canvas and return base64 data URL
  function compressAndEncode(file, maxWidth = 800, quality = 0.7) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = reject;
      reader.onload = e => {
        const img = new Image();
        img.onerror = reject;
        img.onload = () => {
          const canvas = document.createElement('canvas');
          let w = img.width, h = img.height;
          if (w > maxWidth) { h = Math.round(h * maxWidth / w); w = maxWidth; }
          canvas.width = w; canvas.height = h;
          canvas.getContext('2d').drawImage(img, 0, 0, w, h);
          resolve(canvas.toDataURL('image/jpeg', quality));
        };
        img.src = e.target.result;
      };
      reader.readAsDataURL(file);
    });
  }

  // Convert file to base64 data URL
  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = reject;
      reader.onload = e => resolve(e.target.result);
      reader.readAsDataURL(file);
    });
  }

  // Profile icon handlers
  document.getElementById("profile")?.addEventListener("click", () => { window.location.href = "profile.html"; });
  document.getElementById("headerProfile")?.addEventListener("click", () => { window.location.href = "profile.html"; });

  // Load top contributors
  loadTopContributors();
});

// Load top contributors
async function loadTopContributors() {
  try {
    const loadingEl = document.getElementById('contributorsLoading');
    const listEl = document.getElementById('contributorsList');
    const emptyEl = document.getElementById('contributorsEmpty');

    if (!loadingEl || !listEl || !emptyEl) return;

    const { API_CONFIG } = await import('./apiConfig.js');

    const response = await fetch(`${API_CONFIG.BASE_URL}/users/top-contributors`);
    const data = await response.json();

    loadingEl.style.display = 'none';

    if (!data.contributors || data.contributors.length === 0) {
      emptyEl.style.display = 'block';
      return;
    }

    emptyEl.style.display = 'none';

    // Filter out contributors with 0 places before displaying
    const activeContributors = data.contributors.filter(c => c.places_count > 0);

    // If no active contributors after filtering, show empty state
    if (activeContributors.length === 0) {
      emptyEl.style.display = 'block';
      return;
    }

    // Display only top 3 contributors
    activeContributors.slice(0, 3).forEach((contributor, index) => {
      const contributorEl = document.createElement('div');
      contributorEl.className = 'contributor-item';

      const rankClass = index < 3 ? `rank-${index + 1}` : '';
      const medalIcon = index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : '👤';

      contributorEl.innerHTML = `
        <div class="contributor-rank ${rankClass}">${medalIcon}</div>
        <div class="contributor-info">
          <h4>${contributor.name || 'Anonymous'}</h4>
          <p class="contributor-stats">
            <i class="fa-solid fa-location-dot"></i> ${contributor.places_count} ${contributor.places_count === 1 ? 'place' : 'places'}
          </p>
        </div>
      `;

      listEl.appendChild(contributorEl);
    });

  } catch (error) {
    console.error('Error loading top contributors:', error);
    const loadingEl = document.getElementById('contributorsLoading');
    const emptyEl = document.getElementById('contributorsEmpty');

    if (loadingEl) loadingEl.style.display = 'none';
    if (emptyEl) {
      emptyEl.innerHTML = '<i class="fa-solid fa-exclamation-triangle"></i><p>Failed to load contributors</p>';
      emptyEl.style.display = 'block';
    }
  }
}
