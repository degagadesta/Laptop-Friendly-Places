// API Configuration
export const API_CONFIG = {
    BASE_URL: 'http://localhost:8000',
    ENDPOINTS: {
        // Auth endpoints
        LOGIN: '/auth/login',
        REGISTER: '/auth/register',
        VERIFY_EMAIL: '/auth/verify-email',
        RESEND_VERIFICATION: '/auth/resend-verification',
        REFRESH: '/auth/refresh',
        LOGOUT: '/auth/logout',
        CHANGE_PASSWORD: '/auth/change-password',
        FORGOT_PASSWORD: '/auth/forgot-password',
        RESET_PASSWORD: '/auth/reset-password',

        // User endpoints
        PROFILE: '/users/profile',

        // Places endpoints
        GET_ALL_PLACES: '/places',
        GET_PLACE_BY_ID: '/places/detail',
        CONTRIBUTE_PLACE: '/places/contribute'
    }
};

// Storage keys
export const STORAGE_KEYS = {
    TOKEN: 'lfp_auth_token',
    USER: 'lfp_user_data'
};
