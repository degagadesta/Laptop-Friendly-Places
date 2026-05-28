<?php

require_once __DIR__ . '/../models/PlaceModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';
require_once __DIR__ . '/../services/SupabaseService.php';

class PlacesController {
    private PlaceModel $places;
    private AuthMiddleware $auth;
    private SupabaseService $supabase;

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
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 5;
        $this->json(["success" => true, "places" => $this->places->getNewPlaces($limit)]);
    }
    
    public function getPopular(): void {
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 5;
        $this->json(["success" => true, "places" => $this->places->getPopularPlaces($limit)]);
    }

    public function getById(): void {
        if (!isset($_GET['id'])) { $this->json(["success" => false, "error" => "Place ID required"], 400); return; }
        $id = (int) ($_GET['id']);

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
            $this->json(["success" => false, "error" => "Name and location are required"], 400);
            return;
        }

        // Image is required
        if (empty($data['image_data'])) {
            $this->json(["success" => false, "error" => "Image is required"], 400);
            return;
        }

        // Check if Supabase is available
        if (!$this->supabase) {
            $this->json(["success" => false, "error" => "Storage service not available. Please contact administrator."], 500);
            return;
        }

        // Upload image to Supabase
        $imageResult = $this->supabase->uploadFile(
            $data['image_data'],
            'place_image.jpg',
            'image/jpeg',
            'images'
        );
        
        if (!$imageResult['success']) {
            $errorMsg = $imageResult['error'] ?? 'Unknown error';
            error_log("Image upload failed: " . $errorMsg);
            error_log("Details: " . ($imageResult['details'] ?? 'No details'));
            
            $this->json([
                "success" => false, 
                "error" => "Image upload failed: " . $errorMsg,
                "hint" => "Please ensure the Supabase bucket 'media' exists and is public"
            ], 400);
            return;
        }

        $imageUrl = $imageResult['url'];
        $imagePath = $imageResult['path'];

        // Upload video to Supabase if provided
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
                // Video upload failed, but continue (video is optional)
                error_log("Video upload failed: " . ($videoResult['error'] ?? 'Unknown error'));
            }
        }

        // Create place in database
        $id = $this->places->create([
            'name'          => $name,
            'description'   => trim($data['description'] ?? ''),
            'location'      => $location,
            'wifi_rating'   => (int) ($data['wifi_rating'] ?? 0),
            'power_rating'  => (int) ($data['power_rating'] ?? 0),
            'service_rating'=> (int) ($data['service_rating'] ?? 0),
            'created_by'    => $user['id'],
            'image'         => $imagePath,  // Store Supabase path
            'video'         => $videoPath,  // Store Supabase path
            'image_data'    => null,
            'image_mime'    => null,
        ]);

        $this->json([
            "success" => true,
            "message" => "Place contributed successfully",
            "place_id" => $id,
            "image_url" => $imageUrl,
            "video_url" => $videoUrl
        ], 201);
    }

    // public function update(): void {
    //     $user  = $this->auth->authenticate();
    //     $data  = json_decode(file_get_contents("php://input"), true);
    //     $id    = (int) ($data['id'] ?? $_POST['id'] ?? 0);

    //     if (!$id) { $this->json(["error" => "Place ID required"], 400); return; }

    //     $place = $this->places->findById($id);
    //     if (!$place) { $this->json(["error" => "Place not found"], 404); return; }
    //     if ($place['created_by'] != $user['id']) { $this->json(["error" => "Unauthorized"], 403); return; }

    //     $this->places->update($id, $data['name'] ?? $place['name'], $data['description'] ?? $place['description'], $data['location'] ?? $place['location']);
    //     $this->json(["message" => "Place updated successfully"]);
    // }

    // public function delete(): void {
    //     $user = $this->auth->authenticate();
    //     $id   = (int) ($_POST['id'] ?? json_decode(file_get_contents("php://input"), true)['id'] ?? 0);

    //     if (!$id) { $this->json(["error" => "Place ID required"], 400); return; }

    //     $place = $this->places->findById($id);
    //     if (!$place) { $this->json(["error" => "Place not found"], 404); return; }
    //     if ($place['created_by'] != $user['id']) { $this->json(["error" => "Unauthorized"], 403); return; }

    //     $this->places->delete($id);
    //     $this->json(["message" => "Place deleted successfully"]);
    // }

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
