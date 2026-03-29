<?php
require_once "../../config/env.php";

$key = $_ENV['JWT_SECRET'];
$expiry = $_ENV['JWT_EXPIRY'];

function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function generateJWT($payload) {
    global $key, $expiry;

    $header = base64UrlEncode(json_encode([
        "alg" => "HS256",
        "typ" => "JWT"
    ]));

    $payload['exp'] = time() + $expiry;

    $payload = base64UrlEncode(json_encode($payload));

    $signature = base64UrlEncode(
        hash_hmac("sha256", "$header.$payload", $key, true)
    );

    return "$header.$payload.$signature";
}

function verifyJWT($jwt) {
    global $key;

    $parts = explode('.', $jwt);
    if (count($parts) !== 3) return false;

    list($header, $payload, $signature) = $parts;

    $validSignature = base64UrlEncode(
        hash_hmac("sha256", "$header.$payload", $key, true)
    );

    if ($signature !== $validSignature) return false;

    $data = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);

    if ($data['exp'] < time()) return false;

    return $data;
}
?>
