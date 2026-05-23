<?php

class JwtService {
    private string $secret;

    public function __construct(string $secret = '') {
        $this->secret = $secret ?: ($_ENV['JWT_SECRET'] ?? 'my_secret_key');
    }

    private function base64url_encode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64url_decode(string $data): string {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public function generate(array $payload): string {
        if (!isset($payload['exp'])) {
            $payload['exp'] = time() + 3600;
        }

        $header  = $this->base64url_encode(json_encode(["alg" => "HS256", "typ" => "JWT"]));
        $payload = $this->base64url_encode(json_encode($payload));
        $sig     = $this->base64url_encode(hash_hmac('sha256', "$header.$payload", $this->secret, true));

        return "$header.$payload.$sig";
    }

    public function verify(string $token): array|false {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return false;

        [$header, $payload, $sig] = $parts;

        $expected = $this->base64url_encode(hash_hmac('sha256', "$header.$payload", $this->secret, true));
        if (!hash_equals($expected, $sig)) return false;

        $decoded = json_decode($this->base64url_decode($payload), true);
        if (isset($decoded['exp']) && $decoded['exp'] < time()) return false;

        return $decoded;
    }
}
