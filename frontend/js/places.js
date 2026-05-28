import { placesAPI } from './placesAPI.js';
import { auth } from './auth.js';
import { API_CONFIG } from './apiConfig.js';

let allPlaces = [];
let currentTab = 'all';
let userFavorites = new Set(); // Track user's favorite place IDs

document.addEventListener('DOMContentLoaded', async () => {
    await loadUserFavorites();
    await loadPlaces();
    setupTabs();
    setupSheet();
    setupProfileNavigation();
});

async function loadUserFavorites() {
    if (!auth.isAuthenticated()) return;

    try {
        const response = await fetch(API_CONFIG.BASE_URL + '/favorites', {
            headers: { 'Authorization': `Bearer ${auth.token}` }
        });
        if (response.ok) {
            const favorites = await response.json();
            userFavorites = new Set(favorites.map(f => f.id || f.place_id));
        }
    } catch (error) {
        console.error('Error loading favorites:', error);
    }
}

async function loadPlaces() {
    const loading = document.getElementById('loading');

    try {
        loading.style.display = 'flex';

        allPlaces = await placesAPI.getAllPlaces();

        console.log('Loaded places:', allPlaces);

        loading.style.display = 'none';

        displayPlaces('all');

    } catch (error) {
        console.error('Error loading places:', error);
        loading.innerHTML = '<i class="fa-solid fa-exclamation-circle"></i><span>Failed to load places</span>';
    }
}

async function displayPlaces(tab) {
    const container = document.getElementById(tab);

    if (!container) return;

    container.innerHTML = '<div class="loading"><i class="fa-solid fa-spinner"></i><span>Loading...</span></div>';

    let placesToShow = [];

    try {
        // Fetch data based on tab
        if (tab === 'all') {
            placesToShow = allPlaces;
        } else if (tab === 'new') {
            placesToShow = await placesAPI.getNewPlaces(10);
        } else if (tab === 'popular') {
            placesToShow = await placesAPI.getPopularPlaces(10);
        }

        container.innerHTML = ''; // Clear loading message

        if (placesToShow.length === 0) {
            container.innerHTML = '<p class="no-places">No places found</p>';
            return;
        }

        placesToShow.forEach(place => {
            const card = createPlaceCard(place);
            container.appendChild(card);
        });
    } catch (error) {
        console.error(`Error loading ${tab} places:`, error);
        container.innerHTML = `<p class="no-places">Failed to load ${tab} places</p>`;
    }
}

function getImageSrc(place) {
    // Priority: image_url (Supabase) > image_data (base64) > image (legacy path)
    if (place.image_url) {
        return place.image_url;
    }
    if (place.image_data && place.image_mime) {
        return `data:${place.image_mime};base64,${place.image_data}`;
    }
    if (place.image) {
        // Check if it's already a full URL
        if (place.image.startsWith('http')) {
            return place.image;
        }
        // Old file-path images — prefix with backend URL
        return `http://localhost:8000/${place.image}`;
    }
    return null;
}

function getVideoSrc(place) {
    // Priority: video_url (Supabase) > video (legacy path)
    if (place.video_url) {
        return place.video_url;
    }
    if (place.video) {
        // Check if it's already a full URL
        if (place.video.startsWith('http')) {
            return place.video;
        }
        // Old file-path videos — prefix with backend URL
        return `http://localhost:8000/${place.video}`;
    }
    return null;
}

function createPlaceCard(place) {
    const card = document.createElement('div');
    card.className = 'place-card';

    const avgRating = ((place.wifi_rating || 0) + (place.power_rating || 0) + (place.service_rating || 0)) / 3;
    const imgSrc = getImageSrc(place);
    const isFavorite = userFavorites.has(place.id);

    card.innerHTML = `
        <div class="place-image">
            ${imgSrc
            ? `<img src="${imgSrc}" alt="${place.name}">`
            : '<div class="no-image"><i class="fa-solid fa-image"></i></div>'
        }
            <button class="favorite-heart ${isFavorite ? 'favorited' : ''}" data-place-id="${place.id}" title="${isFavorite ? 'Remove from favorites' : 'Add to favorites'}">
                <i class="fa-${isFavorite ? 'solid' : 'regular'} fa-heart"></i>
            </button>
        </div>
        <div class="place-info">
            <h3>${place.name || 'Unnamed Place'}</h3>
            <p>${place.description || 'No description available'}</p>
            <div class="place-rating">
                <i class="fa-solid fa-star"></i>
                <span>${avgRating.toFixed(1)}</span>
            </div>
        </div>
    `;

    // Add click handler for the card (but not the heart button)
    card.addEventListener('click', (e) => {
        if (!e.target.closest('.favorite-heart')) {
            showPlaceDetails(place);
        }
    });

    // Add click handler for the heart button
    const heartBtn = card.querySelector('.favorite-heart');
    heartBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await toggleFavorite(place.id, heartBtn);
    });

    return card;
}

async function toggleFavorite(placeId, heartBtn) {
    if (!auth.isAuthenticated()) {
        alert('Please login to add favorites');
        window.location.href = 'login.html';
        return;
    }

    const isFavorite = userFavorites.has(placeId);
    const method = isFavorite ? 'DELETE' : 'POST';

    try {
        heartBtn.disabled = true;

        const response = await fetch(API_CONFIG.BASE_URL + '/favorites', {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${auth.token}`
            },
            body: JSON.stringify({ place_id: placeId })
        });

        if (response.ok) {
            if (isFavorite) {
                userFavorites.delete(placeId);
                heartBtn.classList.remove('favorited');
                heartBtn.querySelector('i').className = 'fa-regular fa-heart';
                heartBtn.title = 'Add to favorites';
            } else {
                userFavorites.add(placeId);
                heartBtn.classList.add('favorited');
                heartBtn.querySelector('i').className = 'fa-solid fa-heart';
                heartBtn.title = 'Remove from favorites';
            }
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to update favorite');
        }
    } catch (error) {
        console.error('Error toggling favorite:', error);
        alert('Failed to update favorite');
    } finally {
        heartBtn.disabled = false;
    }
}

function showPlaceDetails(place) {
    const sheet = document.getElementById('placeSheet');
    const overlay = document.getElementById('sheetOverlay');

    document.getElementById('sheetName').textContent = place.name || 'Unnamed Place';
    document.getElementById('sheetDescription').textContent = place.description || 'No description available';
    document.getElementById('sheetWifi').textContent = place.wifi_rating || 'N/A';
    document.getElementById('sheetRating').textContent = (((place.wifi_rating || 0) + (place.power_rating || 0) + (place.service_rating || 0)) / 3).toFixed(1);

    const powerEl = document.getElementById('sheetPower');
    if (powerEl) powerEl.textContent = place.power_rating || 'N/A';
    const serviceEl = document.getElementById('sheetService');
    if (serviceEl) serviceEl.textContent = place.service_rating || 'N/A';

    // Build media carousel with multiple images and video
    const carousel = document.getElementById('mediaCarousel');
    carousel.innerHTML = '';

    let hasMedia = false;

    // Get primary image
    const imgSrc = getImageSrc(place);
    if (imgSrc) {
        const img = document.createElement('img');
        img.src = imgSrc;
        img.alt = place.name;
        img.className = 'active'; // First image is active
        carousel.appendChild(img);
        hasMedia = true;
    }

    // Get additional images (image_url_2, image_url_3)
    if (place.image_url_2) {
        const img2 = document.createElement('img');
        img2.src = place.image_url_2;
        img2.alt = place.name + ' - Image 2';
        carousel.appendChild(img2);
        hasMedia = true;
    }

    if (place.image_url_3) {
        const img3 = document.createElement('img');
        img3.src = place.image_url_3;
        img3.alt = place.name + ' - Image 3';
        carousel.appendChild(img3);
        hasMedia = true;
    }

    // Get video
    const videoSrc = getVideoSrc(place);
    if (videoSrc) {
        const video = document.createElement('video');
        video.src = videoSrc;
        video.controls = true;
        video.alt = place.name + ' - Video';
        carousel.appendChild(video);
        hasMedia = true;
    }

    // Show no media message if nothing found
    if (!hasMedia) {
        carousel.innerHTML = '<div class="no-media"><i class="fa-solid fa-image"></i><p>No images available</p></div>';
    }

    // Show/hide carousel navigation buttons based on media count
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const mediaItems = carousel.querySelectorAll('img, video');

    if (mediaItems.length > 1) {
        if (prevBtn) prevBtn.style.display = 'flex';
        if (nextBtn) nextBtn.style.display = 'flex';
        // Reset to first slide
        currentSlide = 0;
        showSlide(0);
    } else {
        if (prevBtn) prevBtn.style.display = 'none';
        if (nextBtn) nextBtn.style.display = 'none';
    }

    // Store place id for action buttons
    sheet.dataset.placeId = place.id;

    // Favorite button
    const favBtn = document.getElementById('favBtn');
    if (favBtn) {
        favBtn.onclick = async () => {
            try {
                const { auth } = await import('./auth.js');
                const { API_CONFIG } = await import('./apiConfig.js');
                if (!auth.isAuthenticated()) { alert('Please login to add favorites'); return; }
                await fetch(API_CONFIG.BASE_URL + '/favorites', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${auth.token}` },
                    body: JSON.stringify({ place_id: place.id })
                });
                favBtn.innerHTML = '<i class="fa-solid fa-heart"></i> Saved!';
                favBtn.style.background = '#ff4757';
            } catch (e) { alert('Failed to add favorite'); }
        };
    }

    // Map button
    const mapBtn = document.getElementById('viewMapBtn');
    if (mapBtn && place.location) {
        const parts = place.location.split(',');
        if (parts.length === 2) {
            mapBtn.onclick = () => {
                window.location.href = `map-view.html?lat=${parts[0].trim()}&lng=${parts[1].trim()}&placeId=${place.id}`;
            };
        }
    }

    // Report button
    const reportBtn = document.getElementById('reportBtn');
    if (reportBtn) {
        reportBtn.onclick = () => {
            if (!auth.isAuthenticated()) {
                alert('Please login to report a place');
                window.location.href = 'login.html';
                return;
            }
            showReportModal(place.id);
        };
    }

    sheet.classList.add('active');
    overlay.classList.add('active');
}

function showReportModal(placeId) {
    const modal = document.getElementById('reportModal');
    const form = document.getElementById('reportForm');

    if (!modal || !form) return;

    modal.classList.remove('hidden');

    // Reset form
    form.reset();

    // Handle form submission
    form.onsubmit = async (e) => {
        e.preventDefault();

        const issueType = document.getElementById('issueType').value;
        const description = document.getElementById('desc').value;

        if (!issueType || !description.trim()) {
            alert('Please fill in all fields');
            return;
        }

        try {
            const response = await fetch(API_CONFIG.BASE_URL + '/reports', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.token}`
                },
                body: JSON.stringify({
                    place_id: placeId,
                    reason: issueType,
                    message: description,
                    reported_by: auth.user?.id || 0
                })
            });

            if (response.ok) {
                alert('Report submitted successfully!');
                modal.classList.add('hidden');
                form.reset();
            } else {
                const data = await response.json();
                alert(data.message || 'Failed to submit report');
            }
        } catch (error) {
            console.error('Error submitting report:', error);
            alert('Failed to submit report');
        }
    };

    // Handle cancel button
    const closeModalBtn = document.getElementById('closeModal');
    if (closeModalBtn) {
        closeModalBtn.onclick = () => {
            modal.classList.add('hidden');
            form.reset();
        };
    }

    // Close modal when clicking outside
    modal.onclick = (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
            form.reset();
        }
    };
}

function setupTabs() {
    const tabs = document.querySelectorAll('.tab');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));

            // Add active class to clicked tab
            tab.classList.add('active');

            // Hide all containers
            document.querySelectorAll('.places-container').forEach(c => {
                c.classList.add('hidden');
                c.innerHTML = ''; // Clear content to prevent duplication
            });

            // Show selected container
            const target = tab.dataset.target;
            const container = document.getElementById(target);
            if (container) {
                container.classList.remove('hidden');
                displayPlaces(target);
            }
        });
    });
}

function setupSheet() {
    const closeBtn = document.getElementById('closeSheet');
    const overlay = document.getElementById('sheetOverlay');
    const sheet = document.getElementById('placeSheet');

    const closeSheet = () => {
        sheet.classList.remove('active');
        overlay.classList.remove('active');
    };

    if (closeBtn) closeBtn.addEventListener('click', closeSheet);
    if (overlay) overlay.addEventListener('click', closeSheet);
}

function setupProfileNavigation() {
    const profileIcon = document.getElementById('profile');
    if (profileIcon) {
        profileIcon.addEventListener('click', () => {
            window.location.href = 'profile.html';
        });
    }

    const headerProfile = document.getElementById('headerProfile');
    if (headerProfile) {
        headerProfile.addEventListener('click', () => {
            window.location.href = 'profile.html';
        });
    }
}


// Carousel navigation
let currentSlide = 0;

function showSlide(index) {
    const carousel = document.getElementById('mediaCarousel');
    const items = carousel.querySelectorAll('img, video');

    if (!items.length) return;

    // Pause all videos
    items.forEach(item => {
        if (item.tagName === 'VIDEO') {
            item.pause();
            item.currentTime = 0;
        }
        item.classList.remove('active');
    });

    // Calculate index with wrapping
    currentSlide = (index + items.length) % items.length;

    // Show current slide
    items[currentSlide].classList.add('active');
}

// Setup carousel button listeners
document.addEventListener('DOMContentLoaded', () => {
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');

    if (prevBtn) {
        prevBtn.addEventListener('click', () => showSlide(currentSlide - 1));
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', () => showSlide(currentSlide + 1));
    }
});
