import { API_CONFIG } from './apiConfig.js';
import { auth } from './auth.js';

class PlacesAPI {
    async request(endpoint, options = {}) {
        const url = `${API_CONFIG.BASE_URL}${endpoint}`;
        const config = {
            ...options,
            headers: { 'Content-Type': 'application/json', ...options.headers }
        };
        if (auth.token && !options.skipAuth) {
            config.headers['Authorization'] = `Bearer ${auth.token}`;
        }
        const response = await fetch(url, config);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Request failed');
        return data;
    }

    async getAllPlaces() {
        const data = await this.request(API_CONFIG.ENDPOINTS.GET_ALL_PLACES, { method: 'GET', skipAuth: true });
        return data.places || [];
    }

    async getNewPlaces(limit = 5) {
        const data = await this.request(`${API_CONFIG.ENDPOINTS.GET_ALL_PLACES}/new?limit=${limit}`, { method: 'GET', skipAuth: true });
        return data.places || [];
    }

    async getPopularPlaces(limit = 5) {
        const data = await this.request(`${API_CONFIG.ENDPOINTS.GET_ALL_PLACES}/popular?limit=${limit}`, { method: 'GET', skipAuth: true });
        return data.places || [];
    }

    async getPlaceById(id) {
        const data = await this.request(`${API_CONFIG.ENDPOINTS.GET_PLACE_BY_ID}?id=${id}`, { method: 'GET', skipAuth: true });
        return data.place;
    }

    async contributePlace(placeData) {
        return await this.request(API_CONFIG.ENDPOINTS.CONTRIBUTE_PLACE, {
            method: 'POST', body: JSON.stringify(placeData)
        });
    }
}

export const placesAPI = new PlacesAPI();
