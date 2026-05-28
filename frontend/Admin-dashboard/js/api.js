// Shared API helper for Admin Dashboard
const ADMIN_API = {
    BASE: 'http://localhost:8000',

    getToken() {
        // Use separate admin token key
        return localStorage.getItem('lfp_admin_token');
    },

    async request(path, options = {}) {
        const token = this.getToken();
        const res = await fetch(this.BASE + path, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
                ...(options.headers || {})
            }
        });

        // Handle 401 Unauthorized - token expired
        if (res.status === 401) {
            alert('Your session has expired. Please login again.');
            // Clear only admin credentials
            localStorage.removeItem('lfp_admin_token');
            localStorage.removeItem('lfp_admin_data');
            localStorage.removeItem('adminLoggedIn');
            localStorage.removeItem('adminUsername');
            window.location.href = 'login-admin.html';
            throw new Error('Session expired');
        }

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Request failed');
        return data;
    },

    get(path) { return this.request(path, { method: 'GET' }); },
    post(path, body) { return this.request(path, { method: 'POST', body: JSON.stringify(body) }); },
    put(path, body) { return this.request(path, { method: 'PUT', body: JSON.stringify(body) }); },
    del(path, body) { return this.request(path, { method: 'DELETE', body: JSON.stringify(body) }); },
};

window.ADMIN_API = ADMIN_API;
