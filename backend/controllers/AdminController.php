<?php

require_once __DIR__ . '/../models/UserModel.php';
require_once __DIR__ . '/../models/PlaceModel.php';
require_once __DIR__ . '/../models/ReportModel.php';
require_once __DIR__ . '/../models/FavoriteModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';

/*
Methods for admin:
-> get all users
-> block user
-> get places by id or all places
-> approve place
-> delete a place
-> get all reports
-> update report status
*/
class AdminController {
    // dependecies
    private UserModel $user_model;
    private ReportModel $report_model;
    private PlaceModel $place_model;
    private FavoriteModel $favorite_model;
    private AuthMiddleware $auth_middleware;
    private PDO $conn;

    public function __construct(PDO $conn)
    {
        $this->conn = $conn;
        $this->user_model = new UserModel(conn: $conn);
        $this->report_model = new ReportModel(conn: $conn);
        $this->place_model = new PlaceModel(conn:$conn);
        $this->favorite_model = new FavoriteModel(conn: $conn);
        $this->auth_middleware = new AuthMiddleware(new JwtService());
    }

    // get all users
    public function getAllUsers(): void{
        $this->auth_middleware->requireRole(['admin']);

        $data = $this->user_model->getAll();
        $this->response(content: ['users' => $data]);
    }

    public function blockUser(): void {
        $this->auth_middleware->requireRole(['admin']);
        $data = json_decode(file_get_contents("php://input"), true);
        $blocked = (bool) ($data['blocked'] ?? true);

        if (!isset($data['user_id'])) { $this->response(["error" => "User ID required"], 400); return; }

        $id = (int) ($data['user_id'] ?? 0);


        $is_user = $this->user_model->findById(id: $id);
        if(!$is_user){
            $this->response(content:['error: ' => 'User not found!'], statusCode: 404);
            return;
        }

        $this->user_model->setBlocked($id, $blocked);
        $this->response(["message" => $blocked ? "User blocked" : "User unblocked"]);
    }

    // get all reports or by id
    public function getReports(): void{
        $this->auth_middleware->requireRole(['admin']);
        $place_id = $_GET['place_id'] ?? null;
        $status = $_GET['status'] ?? null;

        $data = $this->report_model->getAll(status: $status, placeId: $place_id); // Fixed parameter order
        $this->response(content: ['data' => $data, 'reports' => $data]); // Return both for compatibility
    }

    // update report status
    public function updateReportStatus(): void {
        $this->auth_middleware->requireRole(['admin']);
        $json = file_get_contents('php://input');
        $data = json_decode($json, true);

        $report_id = $data['report_id'] ?? null;
        $status = $data['status'] ?? null;

        if (!isset($report_id) || !isset($status)){
            $this->response(content: ['error' => 'Invalid request format. report_id and status required'], statusCode: 400);
            return;
        }

        $valid_status = ['pending', 'resolved', 'rejected'];
        if(!in_array($status, $valid_status)){
            $this->response(content: ["error" => "Invalid status. Must be: pending, resolved, or rejected"], statusCode: 400);
            return;
        }

        $is_updated = $this->report_model->updateStatus(id: $report_id, status: $status);
        $this->response(
            $is_updated ? ['success' => true ,'message' => 'Report updated!'] : ['success' => false, 'message'=> 'Report update failed!'],
            $is_updated ? 200 : 400
        );
    }

    public function getAllPlaces(): void{
        $this->auth_middleware->requireRole(['admin']);

        $data = $this->place_model->getAllForAdmin();
        $this->response(content: ['success' => true ,'places' => $data]);
    }

    public function getPendingPlaces(): void{
        $this->auth_middleware->requireRole(['admin']);

        $data = $this->place_model->getAllPending();
        $this->response(content: ['success' => true ,'places' => $data]);
    }

    public function approvePlace(): void {
        $this->auth_middleware->requireRole(['admin']);

        $input = json_decode(file_get_contents('php://input'), true);


        if(!isset($input['place_id'])){
            $this->response(content: ['error' => 'Invalid format. Place id is required'], statusCode: 400);
            return;
        }

        $id = (int) ($input['place_id'] ?? 0);


        $place_found = $this->place_model->findById(id: $id);
        if(!$place_found){
            $this->response(content: ['error' => 'Place not found'], statusCode: 404);
            return;
        }

        $this->place_model->approve(id: $id);
        $this -> response(content: ['success' => true, 'message' => 'Place approved successfully!']);
    }

    public function deletePlace(): void{
        $this->auth_middleware->requireRole(['admin']);

        $input = json_decode(file_get_contents('php://input'), true);

        if(!isset($input['place_id'])){
            $this->response(content: ['error' => 'Invalid format. Place id is required'], statusCode: 400);
            return;
        }

        $id = (int)($input['place_id'] ?? 0);

        $place_found = $this->place_model->findById(id: $id);
        if(!$place_found){
            $this->response(content: ['error' => 'Place not found'], statusCode: 404);
            return;
        }

        try {
            $this->conn->beginTransaction();
            $this->favorite_model->deleteByPlaceId($id);
            $this->place_model->delete(id: $id);
            $this->report_model->resolveByPlaceId($id);
            $this->conn->commit();

            $this->response(content:['success' => true, 'message' => 'Place removed successfully and related reports resolved!']);
        } catch (Throwable $e) {
            if ($this->conn->inTransaction()) {
                $this->conn->rollBack();
            }
            error_log('Admin deletePlace failed: ' . $e->getMessage());
            $this->response(content: ['error' => 'Failed to delete place', 'details' => $e->getMessage()], statusCode: 500);
        }
    }

    private function response(array $content, int $statusCode = 200): void{
        http_response_code($statusCode);
        echo json_encode($content);
    }
}
