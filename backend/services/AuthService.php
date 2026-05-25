<?php

class AuthService {
    public static function hashPassword(string $password): string {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function verifyPassword(string $password, string $hash): bool {
        return password_verify($password, $hash);
    }

    public static function needsRehash(string $hash): bool {
        return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function validatePasswordStrength(string $password): ?string {
        if (strlen($password) < 8)                    return "Password must be at least 8 characters";
        if (!preg_match('/[A-Z]/', $password))         return "Password must contain at least one uppercase letter";
        if (!preg_match('/[a-z]/', $password))         return "Password must contain at least one lowercase letter";
        if (!preg_match('/[0-9]/', $password))         return "Password must contain at least one number";
        return null;
    }

    public static function getClientIp(): string {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        return filter_var(explode(',', $ip)[0], FILTER_VALIDATE_IP) ?: 'unknown';
    }
}
