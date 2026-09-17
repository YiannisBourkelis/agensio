<?php
header('Content-Type: application/json');
$keys = ['REQUEST_METHOD', 'SCRIPT_FILENAME', 'SCRIPT_NAME', 'REQUEST_URI', 'QUERY_STRING', 'REMOTE_ADDR',
         'SERVER_PORT', 'SERVER_NAME', 'SERVER_PROTOCOL', 'HTTPS', 'HTTP_HOST', 'HTTP_X_TEST', 'CONTENT_LENGTH',
         'DOCUMENT_ROOT', 'GATEWAY_INTERFACE'];
echo json_encode(array_intersect_key($_SERVER, array_flip($keys)), JSON_UNESCAPED_SLASHES);
