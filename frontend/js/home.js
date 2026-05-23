import { placesAPI } from './placesAPI.js';

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
    tap: false
});

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors"
}).addTo(homeMap);

// Load places and add markers + update stats
async function loadPlacesOnMap() {
    try {
        const places = await placesAPI.getAllPlaces();

        console.log(`Loaded ${places.length} places`);

        // Update stat cards
        const total = places.length;
        const recent = places.filter(p => {
            if (!p.created_at) return false;
            const created = new Date(p.created_at);
            const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
            return created >= weekAgo;
        }).length;

        const contributors = new Set(places.map(p => p.created_by).filter(Boolean)).size;

        const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
        set('totalPlaces', total);
        set('newAdded', recent);
        set('totalContributors', contributors);
        set('sidebarTotalPlaces', total);

        // Category counts (basic keyword match on name/description)
        const cafes = places.filter(p => /cafe|coffee|café/i.test(p.name + ' ' + (p.description || ''))).length;
        const hotels = places.filter(p => /hotel|lodge|inn/i.test(p.name + ' ' + (p.description || ''))).length;
        set('cafeCount', cafes);
        set('hotelCount', hotels);

        places.forEach(place => {
            if (!place.location) return;

            const locationParts = place.location.split(',');
            if (locationParts.length < 2) return;

            const lat = parseFloat(locationParts[0].trim());
            const lng = parseFloat(locationParts[1].trim());
            if (isNaN(lat) || isNaN(lng)) return;

            const marker = L.marker([lat, lng]).addTo(homeMap);
            marker.bindPopup(`
                <div class="place-popup">
                    <h3>${place.name || 'Unnamed Place'}</h3>
                    <p>${place.description || 'No description'}</p>
                    <div class="ratings">
                        <span>WiFi: ${place.wifi_rating || 'N/A'}/5</span><br>
                        <span>Power: ${place.power_rating || 'N/A'}/5</span><br>
                        <span>Service: ${place.service_rating || 'N/A'}/5</span>
                    </div>
                    <a href="places.html?id=${place.id}">View Details</a>
                </div>
            `);
        });

    } catch (error) {
        console.error("Error loading places:", error);
        ['totalPlaces', 'newAdded', 'totalContributors', 'sidebarTotalPlaces', 'cafeCount', 'hotelCount']
            .forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '—'; });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadPlacesOnMap();
});

const profileIcon = document.getElementById("profile");
if (profileIcon) profileIcon.addEventListener("click", () => { window.location.href = "profile.html"; });

const headerProfile = document.getElementById("headerProfile");
if (headerProfile) headerProfile.addEventListener("click", () => { window.location.href = "profile.html"; });
