import { API_CONFIG, STORAGE_KEYS } from './apiConfig.js';

class Auth {
    constructor() {
        this.token = localStorage.getItem(STORAGE_KEYS.TOKEN);
        const userData = localStorage.getItem(STORAGE_KEYS.USER);
        this.user = userData ? JSON.parse(userData) : null;
    }

    async request(endpoint, options = {}) {
        const url = `${API_CONFIG.BASE_URL}${endpoint}`;
        const config = {
            ...options,
            headers: { 'Content-Type': 'application/json', ...options.headers }
        };
        if (this.token && !options.skipAuth) {
            config.headers['Authorization'] = `Bearer ${this.token}`;
        }
        const response = await fetch(url, config);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Request failed');
        return data;
    }

    async login(email, password) {
        const data = await this.request(API_CONFIG.ENDPOINTS.LOGIN, {
            method: 'POST', body: JSON.stringify({ email, password }), skipAuth: true
        });
        this.setAuth(data.token, data.user);
        return data;
    }

    async register(name, email, password) {
        const data = await this.request(API_CONFIG.ENDPOINTS.REGISTER, {
            method: 'POST', body: JSON.stringify({ name, email, password }), skipAuth: true
        });
        // No auto-login — user must verify email first
        return data;
    }

    logout() {
        localStorage.removeItem(STORAGE_KEYS.TOKEN);
        localStorage.removeItem(STORAGE_KEYS.USER);
        this.token = null;
        this.user = null;
    }

    setAuth(token, user) {
        this.token = token;
        this.user = user;
        localStorage.setItem(STORAGE_KEYS.TOKEN, token);
        localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
    }

    isAuthenticated() { return !!this.token && !!this.user; }
    getCurrentUser() { return this.user; }

    async refreshToken() {
        if (!this.token) return false;
        try {
            const data = await this.request(API_CONFIG.ENDPOINTS.REFRESH, {
                method: 'POST', body: JSON.stringify({ token: this.token })
            });
            this.setAuth(data.token, this.user);
            return true;
        } catch { this.logout(); return false; }
    }

    async verifyEmail(token) {
        return await this.request(`${API_CONFIG.ENDPOINTS.VERIFY_EMAIL}?token=${encodeURIComponent(token)}`, {
            method: 'GET', skipAuth: true
        });
    }

    async resendVerification(email) {
        return await this.request(API_CONFIG.ENDPOINTS.RESEND_VERIFICATION, {
            method: 'POST', body: JSON.stringify({ email }), skipAuth: true
        });
    }

    async forgotPassword(email) {
        return await this.request(API_CONFIG.ENDPOINTS.FORGOT_PASSWORD, {
            method: 'POST', body: JSON.stringify({ email }), skipAuth: true
        });
    }

    async resetPassword(token, password) {
        return await this.request(API_CONFIG.ENDPOINTS.RESET_PASSWORD, {
            method: 'POST', body: JSON.stringify({ token, password }), skipAuth: true
        });
    }

    async changePassword(currentPassword, newPassword) {
        return await this.request(API_CONFIG.ENDPOINTS.CHANGE_PASSWORD, {
            method: 'POST', body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
        });
    }

    async getProfile() {
        return await this.request(API_CONFIG.ENDPOINTS.PROFILE, { method: 'GET' });
    }

    async updateProfile(name) {
        const data = await this.request(API_CONFIG.ENDPOINTS.PROFILE, {
            method: 'PUT', body: JSON.stringify({ name })
        });
        if (data.user) { this.user = data.user; localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(data.user)); }
        return data;
    }
}

export const auth = new Auth();

export function requireAuth() {
    if (!auth.isAuthenticated()) {
        window.location.replace('../pages/login.html');
        return false;
    }
    return true;
}

export function redirectIfAuthenticated() {
    if (auth.isAuthenticated()) {
        window.location.replace('home.html');
        return true;
    }
    return false;
}
