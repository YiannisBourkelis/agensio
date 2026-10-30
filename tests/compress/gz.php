<?php
// An application that compresses itself (W3 Total Cache from PHP, Next.js): passed through
// untouched, never compressed twice, Vary merged in.
header("Content-Type: text/html; charset=utf-8");
header("Content-Encoding: gzip");
header("Vary: Cookie");
echo gzencode(str_repeat("<p>self compressed</p>\n", 300), 6);
