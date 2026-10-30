<?php
// A buffered answer of a CMS home page's size (112 KB; WordPress's is 70 KB, Laravel's welcome page
// 82 KB): above the 64 KB whole-answer limit of steps 3 and 4, under the 256 KB one, compressed whole.
header('Content-Type: text/html; charset=utf-8');
for ($i = 0; $i < 1500; ++$i) echo "<p class=\"entry\">Entry $i of the large page, with enough text to pass the limit.</p>\n";
