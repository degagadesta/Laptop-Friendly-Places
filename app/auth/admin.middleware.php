<?php
require_once __DIR__ . '/auth.middleware.php';

/**
 * Require admin role for accessing endpoint
 * Returns authenticated admin user data
 */
function requireAdmin() {
    return requireRole(['admin']);
}

/**
 * Require admin or moderator role
 * Returns authenticated user data
 */
function requireAdminOrModerator() {
    return requireRole(['admin', 'moderator']);
}
?>