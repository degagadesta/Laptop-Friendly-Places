<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/../../config/env.php';

function sendVerificationEmail(string $toEmail, string $toName, string $token): bool {
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
        $verifyLink = "$appUrl/app/auth/verify_email.php?token=" . urlencode($token);

        $mail->isHTML(true);
        $mail->Subject = 'Verify your email - LaptopFriendlyPlaces';
        $mail->Body    = "
            <h2>Welcome to LaptopFriendlyPlaces, $toName!</h2>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href='$verifyLink' style='padding:10px 20px;background:#4F46E5;color:#fff;text-decoration:none;border-radius:5px;'>Verify Email</a></p>
            <p>Or copy this link: <br>$verifyLink</p>
            <p>This link expires in 24 hours.</p>
            <p>If you didn't create an account, you can ignore this email.</p>
        ";
        $mail->AltBody = "Verify your email: $verifyLink (expires in 24 hours)";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Mailer error: " . $mail->ErrorInfo);
        return false;
    }
}
?>
