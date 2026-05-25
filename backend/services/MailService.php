<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../vendor/autoload.php';

class MailService {
    public function sendVerificationEmail(string $toEmail, string $toName, string $token): bool {
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host       = $_ENV['MAIL_HOST'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $_ENV['MAIL_USERNAME'];
            $mail->Password   = $_ENV['MAIL_PASSWORD'];
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port       = (int) $_ENV['MAIL_PORT'];

            $mail->setFrom($_ENV['MAIL_FROM_ADDRESS'], $_ENV['MAIL_FROM_NAME']);
            $mail->addAddress($toEmail, $toName);

            $appUrl = rtrim($_ENV['APP_URL'], '/');
            $link   = "$appUrl/auth/verify-email?token=" . urlencode($token);

            $mail->isHTML(true);
            $mail->Subject = 'Verify your email - LaptopFriendlyPlaces';
            $mail->Body    = "
                <h2>Welcome to LaptopFriendlyPlaces, $toName!</h2>
                <p>Click below to verify your email address:</p>
                <p><a href='$link' style='padding:10px 20px;background:#4F46E5;color:#fff;text-decoration:none;border-radius:5px;'>Verify Email</a></p>
                <p>Or copy: $link</p>
                <p>Expires in 24 hours. If you didn't register, ignore this email.</p>
            ";
            $mail->AltBody = "Verify your email: $link (expires in 24 hours)";

            $mail->send();
            return true;
        } catch (Exception $e) {
            error_log("MailService error: " . $mail->ErrorInfo);
            return false;
        }
    }
}
