<?php

class FavoriteModel {
    private PDO $conn;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
    }

    public function getByUser(int $userId): array {
        $stmt = $this->conn->prepare("
            SELECT p.*, f.id as favorite_id 
            FROM favorites f 
            JOIN places p ON f.place_id = p.id 
            WHERE f.user_id = ? AND p.status = 'approved'
        ");
        $stmt->execute([$userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function add(int $userId, int $placeId): void {
        $this->conn->prepare("
            INSERT INTO favorites (user_id, place_id) VALUES (?, ?)
        ")->execute([$userId, $placeId]);
    }

    public function remove(int $userId, int $placeId): void {
        $this->conn->prepare("
            DELETE FROM favorites WHERE user_id = ? AND place_id = ?
        ")->execute([$userId, $placeId]);
    }
}
