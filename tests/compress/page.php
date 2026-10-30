<?php
// The step-3 fixture: a page of several KB, with the validators an application sends, so the
// compressed answer's weak ETag, Vary and 304 can be checked (docs/design-compression.md 8).
$body = str_repeat("<p>" . str_repeat("compressible text ", 20) . "</p>\n", 60);
header("Content-Type: text/html; charset=utf-8");
header("ETag: \"page-v1\"");
header("Cache-Control: max-age=60");
if (($_SERVER["HTTP_IF_NONE_MATCH"] ?? "") !== "" && strpos($_SERVER["HTTP_IF_NONE_MATCH"], "\"page-v1\"") !== false) {
    http_response_code(304);
    exit;
}
echo $body;
