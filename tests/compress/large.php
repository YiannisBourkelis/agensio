<?php
// A buffered answer above the whole-answer limit (64 KB): identity with Vary until step 6 compresses
// it in pieces.
header('Content-Type: text/html; charset=utf-8');
for ($i = 0; $i < 1500; ++$i) echo "<p class=\"entry\">Entry $i of the large page, with enough text to pass the limit.</p>\n";
