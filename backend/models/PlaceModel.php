<?php

class PlaceModel {
    private PDO $conn;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
    }

    public function getAll(): array {
        $stmt = $this->conn->prepare("SELECT * FROM places ORDER BY id DESC");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function findById(int $id): array|false {
        $stmt = $this->conn->prepare("SELECT * FROM places WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function create(array $data): int {
        $stmt = $this->conn->prepare("
            INSERT INTO places (name, description, location, wifi_rating, power_rating, service_rating, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $data['name'],
            $data['description'],
            $data['location'],
            $data['image'] ?? null,
            $data['video'] ?? null,
            $data['wifi_rating'],
            $data['power_rating'],
            $data['service_rating'],
            $data['created_by'],
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
}
