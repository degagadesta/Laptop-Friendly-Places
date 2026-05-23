<?php

require_once __DIR__ . '/../models/ReportModel.php';
require_once __DIR__ . '/../models/PlaceModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';

class ReportController {
    private ReportModel $reports;
    private PlaceModel $places;
    private AuthMiddleware $auth;

    public function __construct(PDO $conn) {
        $this->reports = new ReportModel($conn);
        $this->places  = new PlaceModel($conn);
        $this->auth    = new AuthMiddleware(new JwtService());
    }

    public function create(): void {
        $input = json_decode(file_get_contents('php://input'), true);

        $required = ['message', 'place_id', 'reason', 'reported_by'];
        foreach ($required as $field) {
            if (empty(trim($input[$field] ?? ''))) {
                $this->json(['success' => false, 'message' => "Missing field: $field"], 400); return;
            }
        }

        if (!in_array($input['reason'], ReportModel::VALID_REASONS)) {
            $this->json(['success' => false, 'message' => 'Invalid reason'], 400); return;
        }

        if (!$this->places->findById((int) $input['place_id'])) {
            $this->json(['success' => false, 'message' => 'Place not found'], 404); return;
        }

        $report = $this->reports->create([
            'message'     => trim($input['message']),
            'place_id'    => $input['place_id'],
            'reason'      => $input['reason'],
            'reported_by' => $input['reported_by'],
        ]);

        $this->json(['success' => true, 'message' => 'Report created successfully', 'data' => $report], 201);
    }

    private function json(array $data, int $status = 200): void {
        http_response_code($status);
        echo json_encode($data);
    }
}
