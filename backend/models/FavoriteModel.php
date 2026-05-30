<?php

require_once __DIR__ . '/../services/SupabaseService.php';

class FavoriteModel {
    private PDO $conn;
    private ?SupabaseService $supabase = null;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
        try {
            $this->supabase = new SupabaseService();
        } catch (Exception $e) {
            $this->supabase = null;
        }
    }

    private function addMediaUrls(array $places): array {
        if (!$this->supabase) {
            return $places;
        }

        foreach ($places as &$place) {
            if (!empty($place['image']) && !str_starts_with($place['image'], 'http')) {
                $place['image_url'] = $this->supabase->getPublicUrl($place['image']);
            } elseif (!empty($place['image'])) {
                $place['image_url'] = $place['image'];
            }

            if (!empty($place['video']) && !str_starts_with($place['video'], 'http')) {
                $place['video_url'] = $this->supabase->getPublicUrl($place['video']);
            } elseif (!empty($place['video'])) {
                $place['video_url'] = $place['video'];
            }
        }

        return $places;
    }

    public function getByUser(int $userId): array {
        $stmt = $this->conn->prepare("
            SELECT p.*, f.id as favorite_id
            FROM favorites f
            JOIN places p ON f.place_id = p.id
            WHERE f.user_id = ? AND p.status = 'approved'
        ");
        $stmt->execute([$userId]);
        $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $this->addMediaUrls($places);
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

    public function deleteByPlaceId(int $placeId): void {
        $this->conn->prepare("DELETE FROM favorites WHERE place_id = ?")->execute([$placeId]);
    }
}
