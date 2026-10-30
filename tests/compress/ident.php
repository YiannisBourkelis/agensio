<?php
// Content-Encoding: identity is the application's other opt-out (nginx's convention): the field
// is dropped and the body left alone.
header("Content-Type: text/html; charset=utf-8");
header("Content-Encoding: identity");
echo str_repeat("<p>identity by request</p>\n", 300);
