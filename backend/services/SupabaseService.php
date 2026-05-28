<?php

class SupabaseService {
    private string $url;
    private string $serviceKey;
    private string $bucket;

    public function __construct() {
        $this->url = $_ENV['SUPABASE_URL'] ?? '';
        $this->serviceKey = $_ENV['SUPABASE_SERVICE_KEY'] ?? '';
        $this->bucket = $_ENV['SUPABASE_BUCKET'] ?? 'media';

        if (!$this->url || !$this->serviceKey) {
            throw new Exception('Supabase configuration missing');
        }
    }

    /**
     * Upload a file to Supabase Storage
     * 
     * @param string $fileData Base64 encoded file data or raw binary
     * @param string $fileName File name with extension
     * @param string $mimeType MIME type of the file
     * @param string $folder Optional folder path (e.g., 'images', 'videos')
     * @return array ['success' => bool, 'url' => string, 'path' => string, 'error' => string]
     */
    public function uploadFile(string $fileData, string $fileName, string $mimeType, string $folder = ''): array {
        try {
            // Decode base64 if needed
            if (preg_match('/^data:([^;]+);base64,(.+)$/', $fileData, $matches)) {
                $mimeType = $matches[1];
                $fileData = base64_decode($matches[2]);
            } elseif (base64_decode($fileData, true) !== false) {
                $fileData = base64_decode($fileData);
            }

            // Generate unique file name
            $extension = pathinfo($fileName, PATHINFO_EXTENSION);
            $uniqueName = uniqid() . '_' . time() . '.' . $extension;
            $filePath = $folder ? $folder . '/' . $uniqueName : $uniqueName;

            // Upload to Supabase
            $url = "{$this->url}/storage/v1/object/{$this->bucket}/{$filePath}";

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $fileData,
                CURLOPT_HTTPHEADER => [
                    "Authorization: Bearer {$this->serviceKey}",
                    "Content-Type: {$mimeType}",
                    "x-upsert: false"
                ]
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode >= 200 && $httpCode < 300) {
                $publicUrl = "{$this->url}/storage/v1/object/public/{$this->bucket}/{$filePath}";
                
                return [
                    'success' => true,
                    'url' => $publicUrl,
                    'path' => $filePath,
                    'message' => 'File uploaded successfully'
                ];
            } else {
                $error = json_decode($response, true);
                return [
                    'success' => false,
                    'error' => $error['message'] ?? 'Upload failed',
                    'details' => $response
                ];
            }
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Delete a file from Supabase Storage
     * 
     * @param string $filePath Path to the file in storage
     * @return array ['success' => bool, 'message' => string]
     */
    public function deleteFile(string $filePath): array {
        try {
            $url = "{$this->url}/storage/v1/object/{$this->bucket}/{$filePath}";

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST => 'DELETE',
                CURLOPT_HTTPHEADER => [
                    "Authorization: Bearer {$this->serviceKey}"
                ]
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
  

            if ($httpCode >= 200 && $httpCode < 300) {
                return [
                    'success' => true,
                    'message' => 'File deleted successfully'
                ];
            } else {
                return [
                    'success' => false,
                    'error' => 'Delete failed',
                    'details' => $response
                ];
            }
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Get public URL for a file
     * 
     * @param string $filePath Path to the file in storage
     * @return string Public URL
     */
    public function getPublicUrl(string $filePath): string {
        return "{$this->url}/storage/v1/object/public/{$this->bucket}/{$filePath}";
    }

    /**
     * Upload multiple files
     * 
     * @param array $files Array of ['data' => string, 'name' => string, 'mime' => string]
     * @param string $folder Optional folder path
     * @return array Array of upload results
     */
    public function uploadMultipleFiles(array $files, string $folder = ''): array {
        $results = [];
        
        foreach ($files as $file) {
            $result = $this->uploadFile(
                $file['data'],
                $file['name'],
                $file['mime'],
                $folder
            );
            $results[] = $result;
        }

        return $results;
    }
}

