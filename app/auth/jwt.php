<?php

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/'));
}

function createJWT($payload, $secret) {
    $header = [
        "alg" => "HS256",
        "typ" => "JWT"
    ];

    $headerEncoded = base64url_encode(json_encode($header));
    $payloadEncoded = base64url_encode(json_encode($payload));

    $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", $secret, true);
    $signatureEncoded = base64url_encode($signature);

    return "$headerEncoded.$payloadEncoded.$signatureEncoded";
}

function verifyJWT($jwt, $secret = "my_secret_key") {
    $parts = explode('.', $jwt);

    if (count($parts) !== 3) return false;

    [$header, $payload, $signature] = $parts;

    $validSignature = base64url_encode(
        hash_hmac('sha256', "$header.$payload", $secret, true)
    );

    if (!hash_equals($validSignature, $signature)) {
        return false;
    }

    $decoded = json_decode(base64url_decode($payload), true);
    
    // Check expiration
    if (isset($decoded['exp']) && $decoded['exp'] < time()) {
        return false;
    }

    return $decoded;
}

function generateJWT($payload, $secret = "my_secret_key") {
    if (!isset($payload['exp'])) {
        $payload['exp'] = time() + (60 * 60); // 1 hour default
    }
    return createJWT($payload, $secret);
}
?>