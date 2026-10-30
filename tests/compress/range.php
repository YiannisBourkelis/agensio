<?php
// A 206 is never compressed (a slice of the identity bytes, RFC 9110 14).
header("Content-Type: text/plain");
http_response_code(206);
header("Content-Range: bytes 0-9/5000");
echo "0123456789";
