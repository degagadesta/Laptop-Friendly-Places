import { API_CONFIG } from './apiConfig.js';
import { auth } from './auth.js';

// Places API utility
class PlacesAPI {
  // Make API request
  async request(endpoint, options = {}) {
    const url = `${API_CONFIG.BASE_URL}${endpoint}`;

    const config = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    };

    // Add auth token if available and not skipped
    if (auth.token && !options.skipAuth) {
      config.headers['Authorization'] = `Bearer ${auth.token}`;
    }

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error('Places API Error:', error);
      throw error;
    }
  }

  // Get all places
  async getAllPlaces() {
    console.log('GET_ALL_PLACES endpoint:', API_CONFIG.ENDPOINTS.GET_ALL_PLACES);
    console.log('Full API_CONFIG:', API_CONFIG);
    const data = await this.request(API_CONFIG.ENDPOINTS.GET_ALL_PLACES, {
      method: 'GET',
      skipAuth: true
    });
    return data.places || [];
  }

  // Get place by ID
  async getPlaceById(id) {
    const data = await this.request(`${API_CONFIG.ENDPOINTS.GET_PLACE_BY_ID}?id=${id}`, {
      method: 'GET',
      skipAuth: true
    });
    return data.place;
  }

  // Contribute a new place (requires authentication)
  async contributePlace(placeData) {
    const data = await this.request(API_CONFIG.ENDPOINTS.CONTRIBUTE_PLACE, {
      method: 'POST',
      body: JSON.stringify(placeData)
    });
    return data;
  }
}

// Export singleton instance
export const placesAPI = new PlacesAPI();
