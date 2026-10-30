<?php
// The application's opt-out: Cache-Control: no-transform is honoured (RFC 9111 5.2.2.6).
header("Content-Type: text/html; charset=utf-8");
header("Cache-Control: no-transform, max-age=10");
echo str_repeat("<p>leave me as I am</p>\n", 300);
