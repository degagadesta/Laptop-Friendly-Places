<?php

require_once __DIR__ . '/../models/UserModel.php';
require_once __DIR__ . '/../models/PlaceModel.php';
require_once __DIR__ . '/../models/ReportModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';

class AdminController {
    private UserModel $users;
    private PlaceModel $places;
    private ReportModel $reports;
    private AuthMiddleware $auth;

    public function __construct(PDO $conn) {
        $this->users   = new UserModel($conn);
        $this->places  = new PlaceModel($conn);
        $this->reports = new ReportModel($conn);
        $this->auth    = new AuthMiddleware(new JwtService());
    }

    public function getUsers(): void {
        $this->auth->requireRole(['admin']);
        $this->json(["users" => $this->users->getAll()]);
    }

    public function blockUser(): void {
        $this->auth->requireRole(['admin']);
        $data    = json_decode(file_get_contents("php://input"), true);
        $id      = (int) ($data['user_id'] ?? 0);
        $blocked = (bool) ($data['blocked'] ?? true);

        if (!$id) { $this->json(["error" => "User ID required"], 400); return; }

        $this->users->setBlocked($id, $blocked);
        $this->json(["message" => $blocked ? "User blocked" : "User unblocked"]);
    }

    public function getPlaces(): void {
        $this->auth->requireRole(['admin']);
        $this->json(["success" => true, "places" => $this->places->getAll()]);
    }

    public function approvePlace(): void {
        $this->auth->requireRole(['admin']);
        $data = json_decode(file_get_contents("php://input"), true);
        $id   = (int) ($data['place_id'] ?? 0);

        if (!$id) { $this->json(["error" => "Place ID required"], 400); return; }

        $this->places->approve($id);
        $this->json(["message" => "Place approved"]);
    }

    public function deletePlace(): void {
        $this->auth->requireRole(['admin']);
        $data = json_decode(file_get_contents("php://input"), true);
        $id   = (int) ($data['place_id'] ?? 0);

        if (!$id) { $this->json(["error" => "Place ID required"], 400); return; }

        $this->places->delete($id);
        $this->json(["message" => "Place deleted"]);
    }

    public function getReports(): void {
        $this->auth->requireRole(['admin']);
        $status  = $_GET['status'] ?? null;
        $placeId = $_GET['place_id'] ?? null;
        $this->json(["success" => true, "data" => $this->reports->getAll($status, $placeId)]);
    }

    public function updateReport(): void {
        $this->auth->requireRole(['admin']);
        $data   = json_decode(file_get_contents("php://input"), true);
        $id     = $data['report_id'] ?? '';
        $status = $data['status'] ?? '';

        $valid = ['pending', 'resolved', 'rejected'];
        if (!$id || !in_array($status, $valid)) {
            $this->json(["error" => "Invalid report_id or status"], 400); return;
        }

        $updated = $this->reports->updateStatus($id, $status);
        $this->json($updated
            ? ["success" => true, "message" => "Report updated"]
            : ["success" => false, "message" => "Report not found"], $updated ? 200 : 404);
    }

    private function json(array $data, int $status = 200): void {
        http_response_code($status);
        echo json_encode($data);
    }
}
