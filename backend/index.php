<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/config/env.php';
require_once __DIR__ . '/config/db.php';

require_once __DIR__ . '/controllers/AuthController.php';
require_once __DIR__ . '/controllers/PlacesController.php';
require_once __DIR__ . '/controllers/FavoritesController.php';
require_once __DIR__ . '/controllers/UsersController.php';
require_once __DIR__ . '/controllers/ReportController.php';
require_once __DIR__ . '/controllers/AdminController.php';

$method = $_SERVER['REQUEST_METHOD'];
$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri    = rtrim(preg_replace('#^/backend#', '', $uri), '/');

$auth    = new AuthController($conn);
$places  = new PlacesController($conn);
$favs    = new FavoritesController($conn);
$users   = new UsersController($conn);
$reports = new ReportController($conn);
$admin   = new AdminController($conn);

match (true) {
    // Auth
    $uri === '/auth/register'             && $method === 'POST' => $auth->register(),
    $uri === '/auth/login'                && $method === 'POST' => $auth->login(),
    $uri === '/auth/verify-email'         && $method === 'GET'  => $auth->verifyEmail(),
    $uri === '/auth/resend-verification'  && $method === 'POST' => $auth->resendVerification(),
    $uri === '/auth/forgot-password'      && $method === 'POST' => $auth->forgotPassword(),
    $uri === '/auth/reset-password'       && $method === 'POST' => $auth->resetPassword(),
    $uri === '/auth/change-password'      && $method === 'POST' => $auth->changePassword(),
    $uri === '/auth/refresh'              && $method === 'POST' => $auth->refreshToken(),
    $uri === '/auth/logout'               && $method === 'POST' => $auth->logout(),

    // Places
    $uri === '/places'                    && $method === 'GET'  => $places->getAll(),
    $uri === '/places/new'                && $method === 'GET'  => $places->getNew(),
    $uri === '/places/popular'            && $method === 'GET'  => $places->getPopular(),
    // $uri === '/places'                    && $method === 'POST' => $places->create(),
    $uri === '/places/contribute'         && $method === 'POST' => $places->contribute(),
    $uri === '/places/detail'             && $method === 'GET'  => $places->getById(),
    // $uri === '/places/update'             && $method === 'PUT'  => $places->update(),
    // $uri === '/places/delete'             && $method === 'DELETE' => $places->delete(),

    // Favorites
    $uri === '/favorites'                 && $method === 'GET'  => $favs->get(),
    $uri === '/favorites'                 && $method === 'POST' => $favs->add(),
    $uri === '/favorites'                 && $method === 'DELETE' => $favs->remove(),

    // Users
    $uri === '/users/profile'             && $method === 'GET'  => $users->getProfile(),
    $uri === '/users/profile'             && $method === 'PUT'  => $users->updateProfile(),
    $uri === '/users/top-contributors'    && $method === 'GET'  => $users->getTopContributors(),

    // Reports
    $uri === '/reports'                   && $method === 'POST' => $reports->create(),

    // Admin
    $uri === '/admin/users' && $method === 'GET'  => $admin->getAllUsers(),
    $uri === '/admin/users/block' && $method === 'POST' => $admin->blockUser(),
    $uri === '/admin/places' && $method === 'GET'  => $admin->getAllPlaces(),
    $uri === '/admin/places/pending' && $method === 'GET'  => $admin->getPendingPlaces(),
    $uri === '/admin/places/approve' && $method === 'POST' => $admin->approvePlace(),
    $uri === '/admin/places/delete' && $method === 'DELETE' => $admin->deletePlace(),
    $uri === '/admin/reports' && $method === 'GET'  => $admin->getReports(),
    $uri === '/admin/reports' && $method === 'POST' => $admin->updateReportStatus(),

    default => (function() {
        http_response_code(404);
        echo json_encode(["error" => "Route not found"]);
    })()
};
