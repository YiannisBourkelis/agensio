<?php
// A script that sends its own Content-Length, as a download script does: a HEAD passes it through
// (RFC 9110 8.6), a GET sends the body's.
header('Content-Type: text/plain');
header('Content-Length: 12345');
echo str_repeat('x', 12345);
