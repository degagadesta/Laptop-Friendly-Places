<?php

require_once __DIR__ . '/../models/UserModel.php';
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../services/JwtService.php';
require_once __DIR__ . '/../services/MailService.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class AuthController {
    private UserModel $users;
    private JwtService $jwt;
    private MailService $mailer;
    private AuthMiddleware $auth;

    private const MAX_ATTEMPTS   = 5;
    private const LOCKOUT_SECS   = 15 * 60;

    public function __construct(PDO $conn) {
        $this->users  = new UserModel($conn);
        $this->jwt    = new JwtService();
        $this->mailer = new MailService();
        $this->auth   = new AuthMiddleware($this->jwt);
    }

    public function register(): void {
        $data     = json_decode(file_get_contents("php://input"), true);
        $name     = trim(strip_tags($data['name'] ?? ''));
        $email    = trim(filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL));
        $password = $data['password'] ?? '';

        if (!$name || !$email || !$password) {
            $this->json(["error" => "All fields required"], 400); return;
        }
        if (strlen($name) < 2 || strlen($name) > 100) {
            $this->json(["error" => "Name must be between 2 and 100 characters"], 400); return;
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->json(["error" => "Invalid email format"], 400); return;
        }
        if ($err = AuthService::validatePasswordStrength($password)) {
            $this->json(["error" => $err], 400); return;
        }
        if ($this->users->findByEmail($email)) {
            $this->json(["error" => "User already exists"], 409); return;
        }

        $token  = bin2hex(random_bytes(32));
        $expiry = date('Y-m-d H:i:s', strtotime('+24 hours'));
        $id     = $this->users->create($name, $email, AuthService::hashPassword($password), $token, $expiry);

        $sent = $this->mailer->sendVerificationEmail($email, $name, $token);

        $this->json([
            "message" => $sent
                ? "Registration successful. Please check your email to verify your account."
                : "Account created but verification email could not be sent. Contact support.",
            "user" => ["id" => $id, "name" => $name, "email" => $email]
        ], 201);
    }

    public function login(): void {
        $data     = json_decode(file_get_contents("php://input"), true);
        $email    = trim(filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL));
        $password = $data['password'] ?? '';

        if (!$email || !$password) {
            $this->json(["error" => "Email and password required"], 400); return;
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->json(["error" => "Invalid email format"], 400); return;
        }

        $ip          = AuthService::getClientIp();
        $windowStart = date('Y-m-d H:i:s', time() - self::LOCKOUT_SECS);

        if ($this->users->countRecentFailedAttempts($ip, $windowStart) >= self::MAX_ATTEMPTS) {
            $this->json(["error" => "Too many failed attempts. Try again in 15 minutes."], 429); return;
        }

        $user    = $this->users->findByEmail($email);
        $success = $user && AuthService::verifyPassword($password, $user['password']);

        $this->users->logLoginAttempt($ip, $email, $success);

        if (!$success) {
            $this->json(["error" => "Invalid credentials"], 401); return;
        }
        if ($user['is_blocked']) {
            $this->json(["error" => "Account is blocked"], 403); return;
        }
        if (!$user['email_verified']) {
            $this->json(["error" => "Please verify your email before logging in."], 403); return;
        }

        if (AuthService::needsRehash($user['password'])) {
            $this->users->rehashPassword($user['id'], AuthService::hashPassword($password));
        }

        $token = $this->jwt->generate([
            "id" => $user['id'], "email" => $user['email'],
            "role" => $user['role'] ?? 'user', "exp" => time() + 86400 // 24 hours for testing
        ]);

        $this->json([
            "message" => "Login successful",
            "token"   => $token,
            "user"    => ["id" => $user['id'], "name" => $user['name'], "email" => $user['email'], "role" => $user['role'] ?? 'user']
        ]);
    }

    public function verifyEmail(): void {
        $token = trim($_GET['token'] ?? '');
        
        // Get frontend URL from env or use default
        $frontendUrl = $_ENV['FRONTEND_URL'] ?? 'http://127.0.0.1:5500';
        
        if (!$token) {
            // Redirect to login with error
            header('Location: ' . $frontendUrl . '/frontend/pages/login.html?error=token_required');
            exit;
        }

        $user = $this->users->findByVerificationToken($token);
        if (!$user) {
            // Redirect to login with error
            header('Location: ' . $frontendUrl . '/frontend/pages/login.html?error=invalid_token');
            exit;
        }

        if ($user['email_verified']) {
            // Already verified, redirect to login with success message
            header('Location: ' . $frontendUrl . '/frontend/pages/login.html?verified=already');
            exit;
        }

        // Verify the email
        $this->users->verifyEmail($user['id']);

        // Generate JWT token for auto-login
        $jwtToken = $this->jwt->generate([
            "id" => $user['id'],
            "email" => $user['email'],
            "role" => $user['role'] ?? 'user',
            "exp" => time() + 86400 // 24 hours
        ]);

        // Redirect to home page with token and success message
        $redirectUrl = $frontendUrl . '/frontend/pages/home.html?verified=success&token=' . urlencode($jwtToken) . '&user=' . urlencode(json_encode([
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role'] ?? 'user'
        ]));

        header('Location: ' . $redirectUrl);
        exit;
    }

    public function resendVerification(): void {
        $data  = json_decode(file_get_contents("php://input"), true);
        $email = trim(filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL));

        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->json(["error" => "Valid email required"], 400); return;
        }

        $user = $this->users->findByEmail($email);
        $msg  = ["message" => "If your email is registered and unverified, a new link has been sent."];

        if ($user && !$user['email_verified']) {
            $token  = bin2hex(random_bytes(32));
            $expiry = date('Y-m-d H:i:s', strtotime('+24 hours'));
            $this->users->setVerificationToken($user['id'], $token, $expiry);
            $this->mailer->sendVerificationEmail($email, $user['name'], $token);
        }

        $this->json($msg);
    }

    public function forgotPassword(): void {
        $data  = json_decode(file_get_contents("php://input"), true);
        $email = trim($data['email'] ?? '');

        if (!$email) { $this->json(["error" => "Email required"], 400); return; }

        $user = $this->users->findByEmail($email);
        $msg  = ["message" => "If email exists, reset link will be sent"];

        if ($user) {
            $token  = bin2hex(random_bytes(32));
            $expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));
            $this->users->setResetToken($user['id'], $token, $expiry);
            $msg['reset_token'] = $token; // remove in production, send via email
        }

        $this->json($msg);
    }

    public function resetPassword(): void {
        $data     = json_decode(file_get_contents("php://input"), true);
        $token    = $data['token'] ?? '';
        $password = $data['password'] ?? '';

        if (!$token || !$password) { $this->json(["error" => "Token and password required"], 400); return; }
        if ($err = AuthService::validatePasswordStrength($password)) { $this->json(["error" => $err], 400); return; }

        $user = $this->users->findByResetToken($token);
        if (!$user) { $this->json(["error" => "Invalid or expired token"], 400); return; }

        $this->users->updatePassword($user['id'], AuthService::hashPassword($password));
        $this->json(["message" => "Password reset successfully"]);
    }

    public function changePassword(): void {
        $authUser = $this->auth->authenticate();
        $data     = json_decode(file_get_contents("php://input"), true);
        $current  = $data['current_password'] ?? '';
        $new      = $data['new_password'] ?? '';

        if (!$current || !$new) { $this->json(["error" => "Current and new password required"], 400); return; }
        if ($err = AuthService::validatePasswordStrength($new)) { $this->json(["error" => $err], 400); return; }

        $hash = $this->users->getPasswordHash($authUser['id']);
        if (!$hash || !AuthService::verifyPassword($current, $hash)) {
            $this->json(["error" => "Current password is incorrect"], 400); return;
        }

        $this->users->updatePassword($authUser['id'], AuthService::hashPassword($new));
        $this->json(["message" => "Password changed successfully"]);
    }

    public function refreshToken(): void {
        $data  = json_decode(file_get_contents("php://input"), true);
        $token = $data['token'] ?? '';

        if (!$token) { $this->json(["error" => "Token required"], 400); return; }

        $decoded = $this->jwt->verify($token);
        if (!$decoded) { $this->json(["error" => "Invalid or expired token"], 401); return; }

        $user = $this->users->findById($decoded['id']);
        if (!$user) { $this->json(["error" => "User not found"], 404); return; }

        $newToken = $this->jwt->generate([
            "id" => $user['id'], "email" => $user['email'],
            "role" => $user['role'] ?? 'user', "exp" => time() + 3600
        ]);

        $this->json(["message" => "Token refreshed", "token" => $newToken]);
    }

    public function logout(): void {
        $this->auth->authenticate();
        $this->json(["message" => "Logged out successfully"]);
    }

    private function json(array $data, int $status = 200): void {
        http_response_code($status);
        echo json_encode($data);
    }
}
