// Admin add place with Leaflet map

let map = null;
let marker = null;
let selectedCoordinates = null;

document.addEventListener('DOMContentLoaded', function () {
  console.log('Add Place page loaded - using Leaflet');
  if (!initPage()) return;
  initializeMap();
  setupEventListeners();
});

function initializeMap() {
  console.log('Initializing Leaflet map...');
  const mapContainer = document.getElementById('mapContainer');
  if (!mapContainer) {
    console.error('Map container not found');
    return;
  }
  if (!window.L) {
    console.error('Leaflet not loaded');
    showToast('Map library not loaded. Please refresh the page.', 'error');
    return;
  }
  map = L.map('mapContainer').setView([9.032, 38.757], 12);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors',
    maxZoom: 19
  }).addTo(map);
  map.on('click', function(e) {
    setLocation(e.latlng.lat, e.latlng.lng);
  });
  console.log('Leaflet map initialized successfully');
}

function setLocation(lat, lng) {
  console.log(Location selected: , );
  if (marker) {
    map.removeLayer(marker);
  }
  marker = L.marker([lat, lng]).addTo(map);
  selectedCoordinates = { lat, lng };
  document.getElementById('latitude').value = lat;
  document.getElementById('longitude').value = lng;
  const locationInfo = document.getElementById('selectedLocationInfo');
  const coordinatesDisplay = document.getElementById('selectedCoordinates');
  if (locationInfo && coordinatesDisplay) {
    coordinatesDisplay.textContent = ${lat.toFixed(6)}, ;
    locationInfo.style.display = 'block';
  }
  showToast('Location selected on map', 'success');
}

function setupEventListeners() {
  console.log('Setting up event listeners...');
  const addPlaceForm = document.getElementById('addPlaceForm');
  if (addPlaceForm) {
    addPlaceForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      console.log('Form submitted');
      await handleAddPlace();
    });
  } else {
    console.error('Add Place form not found!');
  }
}

async function handleAddPlace() {
  console.log('Handling add place...');
  const lat = parseFloat(document.getElementById('latitude').value);
  const lng = parseFloat(document.getElementById('longitude').value);
  if (!lat || !lng) {
    showToast('Please select a location on the map first', 'error');
    return;
  }
  const name = document.getElementById('placeName').value.trim();
  const category = document.getElementById('placeCategory').value;
  const description = document.getElementById('description').value.trim();
  const wifiRating = parseInt(document.getElementById('wifiRating').value) || 3;
  const powerRating = parseInt(document.getElementById('powerRating').value) || 3;
  const serviceRating = parseInt(document.getElementById('serviceRating').value) || 3;
  if (!name) {
    showToast('Please enter a place name', 'error');
    return;
  }
  if (!category) {
    showToast('Please select a place category', 'error');
    return;
  }
  const placeData = {
    name: name,
    description: description || A  in Addis Ababa,
    category: category,
    location: ${lat},,
    wifi_rating: wifiRating,
    power_rating: powerRating,
    service_rating: serviceRating,
    status: 'approved',
    images: []
  };
  try {
    console.log('Adding place via PHP API:', placeData);
    const createRes = await ADMIN_API.post('/places/contribute', placeData);
    if (createRes.place_id) {
      await ADMIN_API.post('/admin/places/approve', { place_id: createRes.place_id });
    }
    showToast(Place "" added successfully!, 'success');
    resetForm();
    setTimeout(() => { window.location.href = 'places.html'; }, 2000);
  } catch (error) {
    console.error('Error adding place:', error);
    showToast('Failed to add place. Please try again.', 'error');
  }
}

function resetForm() {
  const form = document.getElementById('addPlaceForm');
  if (form) {
    form.reset();
  }
  document.getElementById('latitude').value = '';
  document.getElementById('longitude').value = '';
  const locationInfo = document.getElementById('selectedLocationInfo');
  if (locationInfo) {
    locationInfo.style.display = 'none';
  }
  if (marker && map) {
    map.removeLayer(marker);
    marker = null;
  }
  selectedCoordinates = null;
  showToast('Form reset', 'info');
}

function showToast(message, type = 'info') {
  console.log(Toast (): );
  const toast = document.createElement('div');
  toast.className = 	oast toast-;
  toast.textContent = message;
  toast.style.cssText = 
    position: fixed;
    top: 20px;
    right: 20px;
    background: ;
    color: white;
    padding: 15px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 10000;
    animation: slideIn 0.3s ease-out;
  ;
  const container = document.getElementById('toastContainer') || document.body;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

window.resetForm = resetForm;
