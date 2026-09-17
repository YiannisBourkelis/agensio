<?php
http_response_code(201);
header('X-Custom: v');
setcookie('a', '1');
setcookie('b', '2');
echo 'created';
