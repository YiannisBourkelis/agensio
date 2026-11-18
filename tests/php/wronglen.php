<?php
// A script that lies about its length: the server holds it to the declared value (nginx's rule since
// 1.19.1): whole and shorter is a 502, longer is cut to it; streamed past its head, a short end cuts
// the body. ?d=DECLARED&n=SENT for sizes; &flush=1 sends a first kilobyte at once, so a streaming
// location has the head out before the short end.
if (isset($_GET['d'])) {
    $d = (int)$_GET['d'];
    $n = (int)$_GET['n'];
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . $d);
    if (!empty($_GET['flush'])) { echo str_repeat('x', 1000); flush(); usleep(300000); $n -= 1000; }
    echo str_repeat('x', $n);
    exit;
}
if (($_GET['m'] ?? '') === 'long') { header('Content-Length: 5'); echo str_repeat('x', 100); }
else { header('Content-Length: 100'); echo 'short'; }
