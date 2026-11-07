<?php
// What the application sees of the browser's Accept-Encoding: offload = true keeps it back.
header('Content-Type: text/plain');
echo $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'none';
