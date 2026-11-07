<?php
// A buffered answer above the whole-answer limit (256 KB, compress_answer::kWholeMax): compressed in
// pieces as it is sent (step 6), chunked on HTTP/1.1; as it came, with Vary, to an HTTP/1.0 client.
header('Content-Type: text/html; charset=utf-8');
for ($i = 0; $i < 4000; ++$i) echo "<p class=\"entry\">Entry $i of the huge page, with enough text to pass the whole-answer limit.</p>\n";
