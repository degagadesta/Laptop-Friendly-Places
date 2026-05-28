<?php

require_once __DIR__ . '/../models/UserModel.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../services/JwtService.php';

class UsersController {
    private UserModel $users;
    private AuthMiddleware $auth;

    public function __construct(PDO $conn) {
        $this->users = new UserModel($conn);
        $this->auth  = new AuthMiddleware(new JwtService());
    }

    public function getProfile(): void {
        $authUser = $this->auth->authenticate();
        $user     = $this->users->findById($authUser['id']);

        if (!$user) { $this->json(["error" => "User not found"], 404); return; }

        $this->json(["user" => $user]);
    }

    public function updateProfile(): void {
        $authUser = $this->auth->authenticate();
        $data     = json_decode(file_get_contents("php://input"), true);
        $name     = trim($data['name'] ?? '');

        if (!$name) { $this->json(["error" => "Name is required"], 400); return; }

        $this->users->updateName($authUser['id'], $name);
        $user = $this->users->findById($authUser['id']);

        $this->json(["message" => "Profile updated successfully", "user" => $user]);
    }

    public function getTopContributors(): void {
        $contributors = $this->users->getTopContributors(10); // Get top 10 contributors
        $this->json(["contributors" => $contributors]);
    }

    private function json(array $data, int $status = 200): void {
        http_response_code($status);
        echo json_encode($data);
    }
}
