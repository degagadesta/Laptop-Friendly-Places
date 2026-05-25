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
        $id = uniqid('report_', true);
        $this->conn->prepare("
            INSERT INTO reports (id, message, place_id, reason, reported_by, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', NOW())
        ")->execute([$id, $data['message'], $data['place_id'], $data['reason'], $data['reported_by']]);

        return $this->findById($id);
    }

    public function findById(string $id): array|false {
        $stmt = $this->conn->prepare("SELECT * FROM reports WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getAll(?string $status = null, ?string $placeId = null): array {
        $where = [];
        $params = [];

        if ($status) { $where[] = "r.status = ?"; $params[] = $status; }
        if ($placeId) { $where[] = "r.place_id = ?"; $params[] = $placeId; }

        $clause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
        $stmt = $this->conn->prepare("
            SELECT r.*, p.name as place_name FROM reports r
            LEFT JOIN places p ON r.place_id = p.id
            $clause ORDER BY r.created_at DESC
        ");
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function updateStatus(string $id, string $status): bool {
        $resolved = $status === 'resolved' ? 'NOW()' : ($status === 'pending' ? 'NULL' : 'resolved_at');
        $stmt = $this->conn->prepare("
            UPDATE reports SET status = ?, resolved_at = $resolved WHERE id = ?
        ");
        $stmt->execute([$status, $id]);
        return $stmt->rowCount() > 0;
    }
}
