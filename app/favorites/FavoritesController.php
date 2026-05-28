<?php

require_once __DIR__ . '/../models/FavoriteModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';

class FavoritesController {
    private FavoriteModel $favorites;
    private AuthMiddleware $auth;

    public function __construct(PDO $conn) {
        $this->favorites = new FavoriteModel($conn);
        $this->auth      = new AuthMiddleware(new JwtService());
    }

    public function get(): void {
        $user = $this->auth->authenticate();
        $this->json($this->favorites->getByUser($user['id']));
    }

    public function add(): void {
        $user    = $this->auth->authenticate();
        $data    = json_decode(file_get_contents("php://input"), true);

        if(!isset($data['place_id'])){
            $this->json(["error" => "Place ID required"], 400);
            return;
        }   

        $placeId = (int) ($data['place_id'] ?? $data['item_id']);

        try {
            $this->favorites->add($user['id'], $placeId);
            $this->json(["message" => "Added to favorites"], 201);
        } catch (PDOException $e) {
            $this->json(["error" => "Already in favorites or failed"], 409);
        }
    }

    public function remove(): void {
        $user    = $this->auth->authenticate();
        $data    = json_decode(file_get_contents("php://input"), true);

        if (!isset($data['place_id'])) { $this->json(["error" => "Place ID required"], 400); return; }

        $placeId = (int) ($data['place_id'] ?? $data['item_id']);

        $this->favorites->remove($user['id'], $placeId);
        $this->json(["message" => "Removed from favorites"]);
    }

    private function json(array $data, int $status = 200): void {
        http_response_code($status);
        echo json_encode($data);
    }
}
