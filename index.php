<?php
// Root router shim for local development.
// This ensures requests started from the repo root still go through the real backend router.
require __DIR__ . '/backend/server.php';
