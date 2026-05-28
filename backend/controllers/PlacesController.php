<?php

require_once __DIR__ . '/../models/PlaceModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';
require_once __DIR__ . '/../services/SupabaseService.php';

class PlacesController {
    private PlaceModel $places;
    private AuthMiddleware $auth;
    private ?SupabaseService $supabase;

    public function __construct(PDO $conn) {
        $this->places = new PlaceModel($conn);
        $this->auth   = new AuthMiddleware(new JwtService());

        try {
            $this->supabase = new SupabaseService();
        } catch (Exception $e) {
            error_log("Supabase initialization failed: " . $e->getMessage());
            $this->supabase = null;
        }
    }

    public function getAll(): void {
        $this->json(["success" => true, "places" => $this->places->getAll()]);
    }

    public function getNew(): void {
        $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 5;
        $this->json(["success" => true, "places" => $this->places->getNewPlaces($limit)]);
    }

    public function getPopular(): void {
        $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 5;
        $this->json(["success" => true, "places" => $this->places->getPopularPlaces($limit)]);
    }

    public function getById(): void {
        if (!isset($_GET['id'])) {
            $this->json(["success" => false, "error" => "Place ID required"], 400);
            return;
        }
        $id = (int) ($_GET['id']);

        $place = $this->places->findById($id);
        if (!$place) {
            $this->json(["success" => false, "error" => "Place not found"], 404);
            return;
        }

        $this->json(["success" => true, "place" => $place]);
    }

    public function contribute(): void {
        $user = $this->auth->authenticate();
        $data = json_decode(file_get_contents("php://input"), true);

        $name = trim($data['name'] ?? '');
        $location = trim($data['location'] ?? '');
        $category = trim($data['category'] ?? '');

        if (!$name || !$location || !$category) {
            $this->json(["success" => false, "error" => "Name, location, and category are required"], 400);
            return;
        }

        $allowedCategories = ['cafe', 'restaurant', 'hotel', 'library', 'coworking', 'other'];
        if (!in_array($category, $allowedCategories, true)) {
            $this->json(["success" => false, "error" => "Invalid category"], 400);
            return;
        }

        $images = $data['images'] ?? [];
        if (!is_array($images)) {
            $images = [];
        }
        $images = array_values(array_filter($images, fn($image) => !empty($image['data'])));

        if (count($images) < 1 || count($images) > 3) {
            $this->json(["success" => false, "error" => "Please provide between 1 and 3 images"], 400);
            return;
        }

        if (!$this->supabase) {
            $this->json(["success" => false, "error" => "Storage service not available. Please contact administrator."], 500);
            return;
        }

        $uploadedImagePaths = [];
        $uploadedImageUrls = [];

        foreach ($images as $index => $image) {
            $mime = $image['mime'] ?? 'image/jpeg';
            $uploadResult = $this->supabase->uploadFile(
                $image['data'],
                'place_image_' . ($index + 1) . '.jpg',
                $mime,
                'images'
            );

            if (!$uploadResult['success']) {
                $errorMsg = $uploadResult['error'] ?? 'Unknown error';
                error_log('Image upload failed: ' . $errorMsg);
                error_log('Details: ' . ($uploadResult['details'] ?? 'No details'));
                $this->json([
                    'success' => false,
                    'error' => 'Image upload failed: ' . $errorMsg,
                    'hint' => "Please ensure the Supabase bucket 'media' exists and is public"
                ], 400);
                return;
            }

            $uploadedImagePaths[] = $uploadResult['path'];
            $uploadedImageUrls[] = $uploadResult['url'];
        }

        $videoUrl = null;
        $videoPath = null;
        if (!empty($data['video_data'])) {
            $videoResult = $this->supabase->uploadFile(
                $data['video_data'],
                'place_video.mp4',
                $data['video_mime'] ?? 'video/mp4',
                'videos'
            );

            if ($videoResult['success']) {
                $videoUrl = $videoResult['url'];
                $videoPath = $videoResult['path'];
            } else {
                error_log('Video upload failed: ' . ($videoResult['error'] ?? 'Unknown error'));
            }
        }

        $id = $this->places->create([
            'name' => $name,
            'description' => trim($data['description'] ?? ''),
            'category' => $category,
            'location' => $location,
            'wifi_rating' => $this->clampRating((int) ($data['wifi_rating'] ?? 0)),
            'power_rating' => $this->clampRating((int) ($data['power_rating'] ?? 0)),
            'service_rating' => $this->clampRating((int) ($data['service_rating'] ?? 0)),
            'created_by' => $user['id'],
            'image' => $uploadedImagePaths[0] ?? null,
            'image_2' => $uploadedImagePaths[1] ?? null,
            'image_3' => $uploadedImagePaths[2] ?? null,
            'video' => $videoPath,
            'image_data' => null,
            'image_mime' => null,
        ]);

        $this->json([
            'success' => true,
            'message' => 'Place contributed successfully',
            'place_id' => $id,
            'image_url' => $uploadedImageUrls[0] ?? null,
            'image_url_2' => $uploadedImageUrls[1] ?? null,
            'image_url_3' => $uploadedImageUrls[2] ?? null,
            'video_url' => $videoUrl
        ], 201);
    }

    private function clampRating(int $rating): int {
        return max(0, min(5, $rating));
    }

    private function json(array $data, int $status = 200): void {
        http_response_code($status);
        echo json_encode($data);
    }
}
