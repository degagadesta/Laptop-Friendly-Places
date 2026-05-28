<?php

class ReportModel {
    private PDO $conn;
    private static bool $schemaEnsured = false;

    public const VALID_REASONS = [
        'incorrect_info', 'inappropriate_content', 'spam',
        'fake_place', 'duplicate', 'closed_permanently', 'other'
    ];

    public function __construct(PDO $conn) {
        $this->conn = $conn;
        $this->ensureSchema();
    }

    private function ensureSchema(): void {
        if (self::$schemaEnsured) {
            return;
        }

        try {
            if (!$this->columnExists('message')) {
                $this->conn->exec("ALTER TABLE reports ADD COLUMN message TEXT NULL AFTER reason");
            }
            if (!$this->columnExists('status')) {
                $this->conn->exec("ALTER TABLE reports ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'pending' AFTER message");
            }
            if (!$this->columnExists('resolved_at')) {
                $this->conn->exec("ALTER TABLE reports ADD COLUMN resolved_at TIMESTAMP NULL DEFAULT NULL AFTER status");
            }

            $this->conn->exec("UPDATE reports SET status = 'pending' WHERE status IS NULL OR status = ''");
            self::$schemaEnsured = true;
        } catch (Throwable $e) {
            error_log('ReportModel schema ensure failed: ' . $e->getMessage());
        }
    }

    private function columnExists(string $columnName): bool {
        $stmt = $this->conn->prepare(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'reports' AND COLUMN_NAME = ?"
        );
        $stmt->execute([$columnName]);
        return (int) $stmt->fetchColumn() > 0;
    }

    public function create(array $data): array {
        $this->conn->prepare("
            INSERT INTO reports (user_id, place_id, reason, message, status)
            VALUES (?, ?, ?, ?, 'pending')
        ")->execute([
            $data['reported_by'],
            $data['place_id'],
            $data['reason'],
            $data['message'] ?? null,
        ]);

        return $this->findById($this->conn->lastInsertId());
    }

    public function findById($id): array|false {
        $stmt = $this->conn->prepare("
            SELECT r.*, p.name as place_name, p.location, u.name as reported_by_name, u.name as reported_by
            FROM reports r
            LEFT JOIN places p ON r.place_id = p.id
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.id = ?
        ");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getAll(?string $status = null, ?string $placeId = null): array {
        $where = [];
        $params = [];

        if ($status) {
            $where[] = "r.status = ?";
            $params[] = $status;
        }
        if ($placeId) {
            $where[] = "r.place_id = ?";
            $params[] = $placeId;
        }

        $clause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
        $stmt = $this->conn->prepare("
            SELECT r.*, p.name as place_name, p.location, u.name as reported_by_name, u.name as reported_by
            FROM reports r
            LEFT JOIN places p ON r.place_id = p.id
            LEFT JOIN users u ON r.user_id = u.id
            $clause
            ORDER BY r.id DESC
        ");
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function updateStatus(string $id, string $status): bool {
        $stmt = $this->conn->prepare("
            UPDATE reports
            SET status = ?, resolved_at = CASE WHEN ? = 'pending' THEN NULL ELSE CURRENT_TIMESTAMP END
            WHERE id = ?
        ");
        $stmt->execute([$status, $status, $id]);
        return $stmt->rowCount() > 0;
    }

    public function resolveByPlaceId(int $placeId): void {
        $this->conn->prepare("
            UPDATE reports
            SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP
            WHERE place_id = ? AND status <> 'resolved'
        ")->execute([$placeId]);
    }

    public function deleteByPlaceId(int $placeId): void {
        $this->conn->prepare("DELETE FROM reports WHERE place_id = ?")->execute([$placeId]);
    }
}
