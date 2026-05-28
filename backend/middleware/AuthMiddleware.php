<?php

require_once __DIR__ . '/../services/JwtService.php';

class AuthMiddleware {
    private JwtService $jwt;

    public function __construct(JwtService $jwt) {
        $this->jwt = $jwt;
    }

    public function authenticate(): array {
        $headers = getallheaders();
        $auth    = $headers['Authorization'] ?? $headers['authorization'] ?? '';

        if (!$auth) {
            http_response_code(401);
            echo json_encode(["error" => "Unauthorized"]);
            exit;
        }

        $token   = str_replace("Bearer ", "", $auth);
        $decoded = $this->jwt->verify($token);

        if (!$decoded) {
            http_response_code(401);
            echo json_encode(["error" => "Invalid or expired token"]);
            exit;
        }

        return $decoded;
    }

    public function requireRole(array $roles): array {
        $user = $this->authenticate();

        if (!empty($roles) && !in_array($user['role'] ?? 'user', $roles)) {
            http_response_code(403);
            echo json_encode(["error" => "Forbidden: Insufficient permissions"]);
            exit;
        }

        return $user;
    }

    public function optionalAuth(): ?array {
        $headers = getallheaders();
        $auth    = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        if (!$auth) return null;
        return $this->jwt->verify(str_replace("Bearer ", "", $auth)) ?: null;
    }
}
