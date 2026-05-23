<?php
require_once 'vendor/autoload.php';
require_once 'config/db.php';

use Kreait\Firebase\Factory;
use Kreait\Firebase\ServiceAccount;

class FirestoreToMySQLMigration {
    private $firestore;
    private $pdo;
    
    public function __construct() {
        // Initialize Firebase
        $factory = (new Factory)
            ->withServiceAccount('path/to/your/firebase-service-account.json'); // Update this path
        
        $this->firestore = $factory->createFirestore();
        
        // Use existing database connection
        global $conn;
        $this->pdo = $conn;
    }
    
    public function migrate() {
        try {
            echo "Starting migration from Firestore to MySQL...\n";
            
            // Step 1: Create places table
            $this->createPlacesTable();
            
            // Step 2: Get all places from Firestore
            $places = $this->getPlacesFromFirestore();
            
            // Step 3: Insert places into MySQL
            $this->insertPlacesToMySQL($places);
            
            echo "Migration completed successfully!\n";
            
        } catch (Exception $e) {
            echo "Migration failed: " . $e->getMessage() . "\n";
        }
    }
    
    private function createPlacesTable() {
        echo "Creating places table...\n";
        
        $sql = "CREATE TABLE IF NOT EXISTS places (
            id VARCHAR(255) PRIMARY KEY,
            category VARCHAR(255),
            description TEXT,
            location_lat DECIMAL(10, 8),
            location_lng DECIMAL(11, 8),
            media_images JSON,
            media_videos JSON,
            name VARCHAR(255) NOT NULL,
            rating_customer_service VARCHAR(50),
            rating_overall DECIMAL(3, 2),
            rating_power VARCHAR(50),
            rating_wifi VARCHAR(50),
            status VARCHAR(50),
            tag VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )";
        
        $this->pdo->exec($sql);
        echo "Places table created successfully.\n";
    }
    
    private function getPlacesFromFirestore() {
        echo "Fetching places from Firestore...\n";
        
        $collection = $this->firestore->database()->collection('places');
        $documents = $collection->documents();
        
        $places = [];
        foreach ($documents as $document) {
            if ($document->exists()) {
                $data = $document->data();
                $data['id'] = $document->id();
                $places[] = $data;
            }
        }
        
        echo "Fetched " . count($places) . " places from Firestore.\n";
        return $places;
    }
    
    private function insertPlacesToMySQL($places) {
        echo "Inserting places into MySQL...\n";
        
        $sql = "INSERT INTO places (
            id, category, description, location_lat, location_lng, 
            media_images, media_videos, name, rating_customer_service, 
            rating_overall, rating_power, rating_wifi, status, tag
        ) VALUES (
            :id, :category, :description, :location_lat, :location_lng,
            :media_images, :media_videos, :name, :rating_customer_service,
            :rating_overall, :rating_power, :rating_wifi, :status, :tag
        )";
        
        $stmt = $this->pdo->prepare($sql);
        
        $successCount = 0;
        $errorCount = 0;
        
        foreach ($places as $place) {
            try {
                // Extract location coordinates
                $locationLat = null;
                $locationLng = null;
                if (isset($place['location']) && is_array($place['location'])) {
                    $locationLat = $place['location']['lat'] ?? null;
                    $locationLng = $place['location']['lng'] ?? null;
                }
                
                // Extract media arrays
                $mediaImages = isset($place['media']['images']) ? json_encode($place['media']['images']) : json_encode([]);
                $mediaVideos = isset($place['media']['videos']) ? json_encode($place['media']['videos']) : json_encode([]);
                
                // Extract rating values
                $ratingCustomerService = $place['rating']['customer_service'] ?? null;
                $ratingOverall = $place['rating']['overall'] ?? null;
                $ratingPower = $place['rating']['power'] ?? null;
                $ratingWifi = $place['rating']['wifi'] ?? null;
                
                $stmt->execute([
                    ':id' => $place['id'],
                    ':category' => $place['category'] ?? null,
                    ':description' => $place['description'] ?? null,
                    ':location_lat' => $locationLat,
                    ':location_lng' => $locationLng,
                    ':media_images' => $mediaImages,
                    ':media_videos' => $mediaVideos,
                    ':name' => $place['name'] ?? '',
                    ':rating_customer_service' => $ratingCustomerService,
                    ':rating_overall' => $ratingOverall,
                    ':rating_power' => $ratingPower,
                    ':rating_wifi' => $ratingWifi,
                    ':status' => $place['status'] ?? null,
                    ':tag' => $place['tag'] ?? null
                ]);
                
                $successCount++;
                
            } catch (Exception $e) {
                $errorCount++;
                echo "Error inserting place {$place['id']}: " . $e->getMessage() . "\n";
            }
        }
        
        echo "Insertion completed: {$successCount} successful, {$errorCount} errors.\n";
    }
}

// Run the migration
try {
    $migration = new FirestoreToMySQLMigration();
    $migration->migrate();
} catch (Exception $e) {
    echo "Failed to initialize migration: " . $e->getMessage() . "\n";
}

?>
    