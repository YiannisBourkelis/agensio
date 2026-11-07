<?php
// An answer past the FastCGI buffer's memory (1 MB): spilled to a temp file, then compressed in
// pieces from it (step 6).
header('Content-Type: text/html; charset=utf-8');
for ($i = 0; $i < 20000; ++$i) echo "<p class=\"entry\">Entry $i of the spilled page, past the buffer's memory.</p>\n";
