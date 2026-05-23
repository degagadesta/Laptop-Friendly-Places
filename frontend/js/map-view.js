import { placesAPI } from './placesAPI.js';

const urlParams = new URLSearchParams(window.location.search);
const targetLat = parseFloat(urlParams.get('lat'));
const targetLng = parseFloat(urlParams.get('lng'));
const targetPlaceId = urlParams.get('placeId');

const redIcon = L.icon({
  iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});

export async function loadPlaces() {
  // Initialize map here so the DOM element is guaranteed to exist
  const map = L.map("mapViewMap").setView([9.03, 38.74], 13);

  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors"
  }).addTo(map);

  try {
    const places = await placesAPI.getAllPlaces();

    places.forEach(place => {
      if (!place.location) return;

      const parts = place.location.split(',');
      if (parts.length < 2) return;

      const lat = parseFloat(parts[0].trim());
      const lng = parseFloat(parts[1].trim());
      if (isNaN(lat) || isNaN(lng)) return;

      const isTarget = targetPlaceId && String(place.id) === String(targetPlaceId);
      const marker = L.marker([lat, lng], isTarget ? { icon: redIcon } : {}).addTo(map);

      if (isTarget) {
        map.setView([lat, lng], 16);
        marker.openPopup();
      }

      marker.bindPopup(`
                <div class="map-card">
                    <div class="map-card-body">
                        <h3>${place.name || 'Unnamed Place'}</h3>
                        <p class="desc">${place.description || ''}</p>
                        <div class="ratings">
                            <span>📶 Wi-Fi: ${place.wifi_rating ?? 'N/A'}</span><br>
                            <span>🔌 Power: ${place.power_rating ?? 'N/A'}</span><br>
                            <span>😊 Service: ${place.service_rating ?? 'N/A'}</span>
                        </div>
                        <a href="places.html?id=${place.id}">View Details</a>
                    </div>
                </div>
            `);
    });

    // Pan to lat/lng if passed directly in URL
    if (!targetPlaceId && !isNaN(targetLat) && !isNaN(targetLng)) {
      map.setView([targetLat, targetLng], 16);
    }

  } catch (err) {
    console.error("Error loading places on map:", err);
  }
}
