<?php

require_once __DIR__ . '/../models/PlaceModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';

class PlacesController {
    private PlaceModel $places;
    private AuthMiddleware $auth;

    public function __construct(PDO $conn) {
        $this->places = new PlaceModel($conn);
        $this->auth   = new AuthMiddleware(new JwtService());
    }

    public function getAll(): void {
        $this->json(["success" => true, "places" => $this->places->getAll()]);
    }

    public function getById(): void {
        $id = (int) ($_GET['id'] ?? 0);
        if (!$id) { $this->json(["success" => false, "error" => "Place ID required"], 400); return; }

        $place = $this->places->findById($id);
        if (!$place) { $this->json(["success" => false, "error" => "Place not found"], 404); return; }

        $this->json(["success" => true, "place" => $place]);
    }

    public function contribute(): void {
        $user = $this->auth->authenticate();
        $data = json_decode(file_get_contents("php://input"), true);

        $name     = trim($data['name'] ?? '');
        $location = trim($data['location'] ?? '');

        if (!$name || !$location) {
            $this->json(["success" => false, "error" => "Name and location are required"], 400); return;
        }

        $id = $this->places->create([
            'name'          => $name,
            'description'   => trim($data['description'] ?? ''),
            'location'      => $location,
            'wifi_rating'   => (int) ($data['wifi_rating'] ?? 0),
            'power_rating'  => (int) ($data['power_rating'] ?? 0),
            'service_rating'=> (int) ($data['service_rating'] ?? 0),
            'created_by'    => $user['id'],
        ]);

        $this->json(["success" => true, "message" => "Place contributed successfully", "place_id" => $id], 201);
    }

    public function create(): void {
        $user = $this->auth->authenticate();

        $name        = trim($_POST['name'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $location    = trim($_POST['location'] ?? '');
        $imagePath   = $this->handleUpload('image', 'uploads/images');
        $videoPath   = $this->handleUpload('video', 'uploads/videos');

        $id = $this->places->createWithMedia([
            'name'        => $name,
            'description' => $description,
            'location'    => $location,
            'image'       => $imagePath,
            'video'       => $videoPath,
            'created_by'  => $user['id'],
        ]);

        $this->json(["success" => true, "message" => "Place created successfully", "place_id" => $id], 201);
    }

    public function update(): void {
        $user  = $this->auth->authenticate();
        $data  = json_decode(file_get_contents("php://input"), true);
        $id    = (int) ($data['id'] ?? $_POST['id'] ?? 0);

        if (!$id) { $this->json(["error" => "Place ID required"], 400); return; }

        $place = $this->places->findById($id);
        if (!$place) { $this->json(["error" => "Place not found"], 404); return; }
        if ($place['created_by'] != $user['id']) { $this->json(["error" => "Unauthorized"], 403); return; }

        $this->places->update($id, $data['name'] ?? $place['name'], $data['description'] ?? $place['description'], $data['location'] ?? $place['location']);
        $this->json(["message" => "Place updated successfully"]);
    }

    public function delete(): void {
        $user = $this->auth->authenticate();
        $id   = (int) ($_POST['id'] ?? json_decode(file_get_contents("php://input"), true)['id'] ?? 0);

        if (!$id) { $this->json(["error" => "Place ID required"], 400); return; }

        $place = $this->places->findById($id);
        if (!$place) { $this->json(["error" => "Place not found"], 404); return; }
        if ($place['created_by'] != $user['id']) { $this->json(["error" => "Unauthorized"], 403); return; }

        $this->places->delete($id);
        $this->json(["message" => "Place deleted successfully"]);
    }

    private function handleUpload(string $field, string $dir): ?string {
        if (!isset($_FILES[$field]) || $_FILES[$field]['error'] !== 0) return null;

        $uploadDir = __DIR__ . "/../../$dir/";
        if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);

        $filename = time() . "_" . basename($_FILES[$field]['name']);
        if (move_uploaded_file($_FILES[$field]['tmp_name'], $uploadDir . $filename)) {
            return "$dir/$filename";
        }
        return null;
    }

    private function json(array $data, int $status = 200): void {
        http_response_code($status);
        echo json_encode($data);
    }
}
