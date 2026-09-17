<?php
// A script that lies about its length: the server must hold it to the declared value.
if (($_GET['m'] ?? '') === 'long') { header('Content-Length: 5'); echo str_repeat('x', 100); }
else { header('Content-Length: 100'); echo 'short'; }
