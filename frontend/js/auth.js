import { API_CONFIG, STORAGE_KEYS } from './apiConfig.js';

// Auth utility class
class Auth {
    constructor() {
        this.token = localStorage.getItem(STORAGE_KEYS.TOKEN);
        const userData = localStorage.getItem(STORAGE_KEYS.USER);
        this.user = userData ? JSON.parse(userData) : null;
    }

    // Make authenticated API request
    async request(endpoint, options = {}) {
        const url = `${API_CONFIG.BASE_URL}${endpoint}`;

        const config = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        };

        // Add auth token if available
        if (this.token && !options.skipAuth) {
            config.headers['Authorization'] = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    // Login
    async login(email, password) {
        const data = await this.request(API_CONFIG.ENDPOINTS.LOGIN, {
            method: 'POST',
            body: JSON.stringify({ email, password }),
            skipAuth: true
        });

        this.setAuth(data.token, data.user);
        return data;
    }

    // Register
    async register(name, email, password) {
        const data = await this.request(API_CONFIG.ENDPOINTS.REGISTER, {
            method: 'POST',
            body: JSON.stringify({ name, email, password }),
            skipAuth: true
        });

        // No auto-login — user must verify email first
        return data;
    }

    // Logout
    logout() {
        localStorage.removeItem(STORAGE_KEYS.TOKEN);
        localStorage.removeItem(STORAGE_KEYS.USER);
        this.token = null;
        this.user = null;
    }

    // Set authentication data
    setAuth(token, user) {
        this.token = token;
        this.user = user;
        localStorage.setItem(STORAGE_KEYS.TOKEN, token);
        localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.token && !!this.user;
    }

    // Get current user
    getCurrentUser() {
        return this.user;
    }

    // Refresh token
    async refreshToken() {
        if (!this.token) return false;

        try {
            const data = await this.request(API_CONFIG.ENDPOINTS.REFRESH, {
                method: 'POST',
                body: JSON.stringify({ token: this.token })
            });

            this.setAuth(data.token, this.user);
            return true;
        } catch (error) {
            this.logout();
            return false;
        }
    }

    // Change password
    async changePassword(currentPassword, newPassword) {
        return await this.request(API_CONFIG.ENDPOINTS.CHANGE_PASSWORD, {
            method: 'POST',
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
    }

    // Verify email via token (called from verify page)
    async verifyEmail(token) {
        return await this.request(`${API_CONFIG.ENDPOINTS.VERIFY_EMAIL}?token=${encodeURIComponent(token)}`, {
            method: 'GET',
            skipAuth: true
        });
    }

    // Resend verification email
    async resendVerification(email) {
        return await this.request(API_CONFIG.ENDPOINTS.RESEND_VERIFICATION, {
            method: 'POST',
            body: JSON.stringify({ email }),
            skipAuth: true
        });
    }

    // Forgot password
    async forgotPassword(email) {
        return await this.request(API_CONFIG.ENDPOINTS.FORGOT_PASSWORD, {
            method: 'POST',
            body: JSON.stringify({ email }),
            skipAuth: true
        });
    }

    // Reset password
    async resetPassword(token, password) {
        return await this.request(API_CONFIG.ENDPOINTS.RESET_PASSWORD, {
            method: 'POST',
            body: JSON.stringify({ token, password }),
            skipAuth: true
        });
    }

    // Get user profile
    async getProfile() {
        return await this.request(API_CONFIG.ENDPOINTS.PROFILE, {
            method: 'GET'
        });
    }

    // Update user profile
    async updateProfile(name) {
        const data = await this.request(API_CONFIG.ENDPOINTS.PROFILE, {
            method: 'PUT',
            body: JSON.stringify({ name })
        });

        // Update stored user data
        if (data.user) {
            this.user = data.user;
            localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(data.user));
        }

        return data;
    }
}

// Export singleton instance
export const auth = new Auth();

// Auth guard for protected pages
export function requireAuth() {
    if (!auth.isAuthenticated()) {
        window.location.replace('../pages/login.html');
        return false;
    }
    return true;
}

// Redirect if already logged in
export function redirectIfAuthenticated() {
    if (auth.isAuthenticated()) {
        window.location.replace('home.html');
        return true;
    }
    return false;
}
