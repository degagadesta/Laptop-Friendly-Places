<?php

require_once __DIR__ . '/../services/SupabaseService.php';

class PlaceModel {
    private PDO $conn;
    private ?SupabaseService $supabase = null;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
        try {
            $this->supabase = new SupabaseService();
        } catch (Exception $e) {
            // Supabase not configured, will fall back to base64
            $this->supabase = null;
        }
    }

    private function addMediaUrls(array $places): array {
        if (!$this->supabase) {
            return $places;
        }

        foreach ($places as &$place) {
            // Convert Supabase paths to public URLs
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

    public function getAll(): array {
        $stmt = $this->conn->prepare("SELECT * FROM places WHERE status = 'approved' ORDER BY id DESC");
        $stmt->execute();
        $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $this->addMediaUrls($places);
    }
    
    public function getNewPlaces(int $limit = 5): array {
        $stmt = $this->conn->prepare("SELECT * FROM places WHERE status = 'approved' ORDER BY created_at DESC LIMIT " . (int)$limit);
        $stmt->execute();
        $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $this->addMediaUrls($places);
    }
    
    public function getPopularPlaces(int $limit = 5): array {
        // For now, return places with highest average rating
        // Later we can implement based on favorites count
        $stmt = $this->conn->prepare("
            SELECT p.*, 
                   ((p.wifi_rating + p.power_rating + p.service_rating) / 3) as avg_rating
            FROM places p 
            WHERE p.status = 'approved' 
            ORDER BY avg_rating DESC 
            LIMIT " . (int)$limit
        );
        $stmt->execute();
        $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $this->addMediaUrls($places);
    }
    
    public function getAllPending(): array {
        $stmt = $this->conn->prepare("SELECT * FROM places WHERE status = 'pending' ORDER BY id DESC");
        $stmt->execute();
        $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $this->addMediaUrls($places);
    }
    
    public function getAllForAdmin(): array {
        $stmt = $this->conn->prepare("SELECT * FROM places ORDER BY id DESC");
        $stmt->execute();
        $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $this->addMediaUrls($places);
    }

    public function findById(int $id): array|false {
        $stmt = $this->conn->prepare("SELECT * FROM places WHERE id = ?");
        $stmt->execute([$id]);
        $place = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($place) {
            $places = $this->addMediaUrls([$place]);
            return $places[0];
        }
        return false;
    }


    public function create(array $data): int {
        $stmt = $this->conn->prepare("
            INSERT INTO places (name, description, location, wifi_rating, power_rating, service_rating, created_by, image, video, image_data, image_mime, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $data['name'],
            $data['description'],
            $data['location'],
            $data['wifi_rating'],
            $data['power_rating'],
            $data['service_rating'],
            $data['created_by'],
            $data['image'] ?? null,      // Supabase path
            $data['video'] ?? null,      // Supabase path
            $data['image_data'] ?? null, // Legacy base64 (for backward compatibility)
            $data['image_mime'] ?? null, // Legacy mime type
            'pending' // Default status for new contributions
        ]);
        return (int) $this->conn->lastInsertId();
    }

    // public function createWithMedia(array $data): int {
    //     $stmt = $this->conn->prepare("
    //         INSERT INTO places (name, description, location, image, video, created_by)
    //         VALUES (?, ?, ?, ?, ?, ?)
    //     ");
    //     $stmt->execute([
    //         $data['name'],
    //         $data['description'],
    //         $data['location'],
    //         $data['image'] ?? null,
    //         $data['video'] ?? null,
    //         $data['created_by'],
    //     ]);
    //     return (int) $this->conn->lastInsertId();
    // }

    public function update(int $id, string $name, string $description, string $location): void {
        $this->conn->prepare("
            UPDATE places SET name = ?, description = ?, location = ? WHERE id = ?
        ")->execute([$name, $description, $location, $id]);
    }

    public function delete(int $id): void {
        $this->conn->prepare("DELETE FROM places WHERE id = ?")->execute([$id]);
    }

    public function approve(int $id): void {
        $this->conn->prepare("UPDATE places SET status = 'approved' WHERE id = ?")->execute([$id]);
    }
    
    public function reject(int $id): void {
        $this->conn->prepare("UPDATE places SET status = 'rejected' WHERE id = ?")->execute([$id]);
    }
    
    public function updateStatus(int $id, string $status): void {
        $this->conn->prepare("UPDATE places SET status = ? WHERE id = ?")->execute([$status, $id]);
    }
}
