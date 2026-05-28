<?php

class UserModel {
    private PDO $conn;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
    }

    public function findByEmail(string $email): array|false {
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function findById(int $id): array|false {
        $stmt = $this->conn->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function create(string $name, string $email, string $hashedPassword, string $token, string $expiry): int {
        $stmt = $this->conn->prepare("
            INSERT INTO users (name, email, password, email_verified, verification_token, verification_token_expiry)
            VALUES (?, ?, ?, 0, ?, ?)
        ");
        $stmt->execute([$name, $email, $hashedPassword, $token, $expiry]);
        return (int) $this->conn->lastInsertId();
    }

    public function verifyEmail(int $id): void {
        $this->conn->prepare("
            UPDATE users SET email_verified = 1, verification_token = NULL, verification_token_expiry = NULL WHERE id = ?
        ")->execute([$id]);
    }

    public function findByVerificationToken(string $token): array|false {
        $stmt = $this->conn->prepare("
            SELECT id, email_verified FROM users WHERE verification_token = ? AND verification_token_expiry > NOW()
        ");
        $stmt->execute([$token]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function setVerificationToken(int $id, string $token, string $expiry): void {
        $this->conn->prepare("
            UPDATE users SET verification_token = ?, verification_token_expiry = ? WHERE id = ?
        ")->execute([$token, $expiry, $id]);
    }

    public function setResetToken(int $id, string $token, string $expiry): void {
        $this->conn->prepare("
            UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?
        ")->execute([$token, $expiry, $id]);
    }

    public function findByResetToken(string $token): array|false {
        $stmt = $this->conn->prepare("
            SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()
        ");
        $stmt->execute([$token]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function updatePassword(int $id, string $hashedPassword): void {
        $this->conn->prepare("
            UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?
        ")->execute([$hashedPassword, $id]);
    }

    public function getPasswordHash(int $id): string|false {
        $stmt = $this->conn->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['password'] : false;
    }

    public function updateName(int $id, string $name): void {
        $this->conn->prepare("UPDATE users SET name = ? WHERE id = ?")->execute([$name, $id]);
    }

    public function rehashPassword(int $id, string $newHash): void {
        $this->conn->prepare("UPDATE users SET password = ? WHERE id = ?")->execute([$newHash, $id]);
    }

    public function getAll(): array {
        $stmt = $this->conn->prepare("SELECT id, name, email, role, is_blocked, created_at FROM users ORDER BY id DESC");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function setBlocked(int $id, bool $blocked): void {
        $this->conn->prepare("UPDATE users SET is_blocked = ? WHERE id = ?")->execute([$blocked ? 1 : 0, $id]);
    }

    public function logLoginAttempt(string $ip, string $email, bool $success): void {
        $this->conn->prepare("
            INSERT INTO login_attempts (ip_address, email, success, attempted_at) VALUES (?, ?, ?, NOW())
        ")->execute([$ip, $email, $success ? 1 : 0]);
    }

    public function countRecentFailedAttempts(string $ip, string $windowStart): int {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempted_at > ? AND success = 0
        ");
        $stmt->execute([$ip, $windowStart]);
        return (int) $stmt->fetchColumn();
    }

    public function getTopContributors(int $limit = 10): array {
        $stmt = $this->conn->prepare("
            SELECT u.id, u.name, u.email, u.role, u.created_at, 
                   COUNT(p.id) as places_count
            FROM users u 
            LEFT JOIN places p ON u.id = p.created_by AND p.status = 'approved'
            GROUP BY u.id 
            ORDER BY places_count DESC, u.name ASC
            LIMIT " . (int)$limit
        );
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
