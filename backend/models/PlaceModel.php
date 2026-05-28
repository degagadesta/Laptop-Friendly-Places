<?php

require_once __DIR__ . '/../services/SupabaseService.php';

class PlaceModel {
    private PDO $conn;
    private ?SupabaseService $supabase = null;
    private static bool $schemaEnsured = false;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
        $this->ensureSchema();
        try {
            $this->supabase = new SupabaseService();
        } catch (Exception $e) {
            // Supabase not configured, will fall back to base64
            $this->supabase = null;
        }
    }

    private function ensureSchema(): void {
        if (self::$schemaEnsured) {
            return;
        }

        try {
            if (!$this->columnExists('category')) {
                $this->conn->exec("ALTER TABLE places ADD COLUMN category VARCHAR(50) NULL AFTER description");
            }
            if (!$this->columnExists('image_2')) {
                $this->conn->exec("ALTER TABLE places ADD COLUMN image_2 TEXT NULL AFTER image");
            }
            if (!$this->columnExists('image_3')) {
                $this->conn->exec("ALTER TABLE places ADD COLUMN image_3 TEXT NULL AFTER image_2");
            }
            self::$schemaEnsured = true;
        } catch (Throwable $e) {
            error_log('PlaceModel schema ensure failed: ' . $e->getMessage());
        }
    }

    private function columnExists(string $columnName): bool {
        $stmt = $this->conn->prepare(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'places' AND COLUMN_NAME = ?"
        );
        $stmt->execute([$columnName]);
        return (int) $stmt->fetchColumn() > 0;
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

            if (!empty($place['image_2']) && !str_starts_with($place['image_2'], 'http')) {
                $place['image_url_2'] = $this->supabase->getPublicUrl($place['image_2']);
            } elseif (!empty($place['image_2'])) {
                $place['image_url_2'] = $place['image_2'];
            }

            if (!empty($place['image_3']) && !str_starts_with($place['image_3'], 'http')) {
                $place['image_url_3'] = $this->supabase->getPublicUrl($place['image_3']);
            } elseif (!empty($place['image_3'])) {
                $place['image_url_3'] = $place['image_3'];
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
        $stmt = $this->conn->prepare("SELECT * FROM places WHERE status <> 'deleted' ORDER BY id DESC");
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
            INSERT INTO places (
                name, description, category, location,
                wifi_rating, power_rating, service_rating, created_by,
                image, image_2, image_3, video,
                image_data, image_mime, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $data['name'],
            $data['description'],
            $data['category'] ?? null,
            $data['location'],
            $data['wifi_rating'],
            $data['power_rating'],
            $data['service_rating'],
            $data['created_by'],
            $data['image'] ?? null,
            $data['image_2'] ?? null,
            $data['image_3'] ?? null,
            $data['video'] ?? null,
            $data['image_data'] ?? null,
            $data['image_mime'] ?? null,
            'pending'
        ]);
        return (int) $this->conn->lastInsertId();
    }

    public function update(int $id, string $name, string $description, string $location): void {
        $this->conn->prepare("
            UPDATE places SET name = ?, description = ?, location = ? WHERE id = ?
        ")->execute([$name, $description, $location, $id]);
    }

    public function delete(int $id): void {
        $this->conn->prepare("UPDATE places SET status = 'deleted' WHERE id = ?")->execute([$id]);
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
