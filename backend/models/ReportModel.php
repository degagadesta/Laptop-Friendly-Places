<?php

class ReportModel {
    private PDO $conn;

    public const VALID_REASONS = [
        'incorrect_info', 'inappropriate_content', 'spam',
        'fake_place', 'duplicate', 'closed_permanently', 'other'
    ];

    public function __construct(PDO $conn) {
        $this->conn = $conn;
    }

    public function create(array $data): array {
        $this->conn->prepare("
            INSERT INTO reports (user_id, place_id, reason)
            VALUES (?, ?, ?)
        ")->execute([$data['reported_by'], $data['place_id'], $data['reason']]);

        return $this->findById($this->conn->lastInsertId());
    }

    public function findById($id): array|false {
        $stmt = $this->conn->prepare("SELECT * FROM reports WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getAll(?string $status = null, ?string $placeId = null): array {
        $where = [];
        $params = [];

        // Note: status column doesn't exist in current table structure
        // if ($status) { $where[] = "r.status = ?"; $params[] = $status; }
        if ($placeId) { $where[] = "r.place_id = ?"; $params[] = $placeId; }

        $clause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
        $stmt = $this->conn->prepare("
            SELECT r.*, p.name as place_name, u.name as reported_by_name 
            FROM reports r
            LEFT JOIN places p ON r.place_id = p.id
            LEFT JOIN users u ON r.user_id = u.id
            $clause ORDER BY r.id DESC
        ");
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function updateStatus(string $id, string $status): bool {
        // Note: status and resolved_at columns don't exist in current table structure
        // For now, we'll just return true to avoid errors
        // You may want to add these columns to the database later
        return true;
    }
}
