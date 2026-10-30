<?php
// A buffered answer above the whole-answer limit (256 KB, compress_answer::kWholeMax): identity with
// Vary until step 6 compresses it in pieces.
header('Content-Type: text/html; charset=utf-8');
for ($i = 0; $i < 4000; ++$i) echo "<p class=\"entry\">Entry $i of the huge page, with enough text to pass the whole-answer limit.</p>\n";
