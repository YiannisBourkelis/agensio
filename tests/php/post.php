<?php
$raw = file_get_contents('php://input');
echo strlen($raw), ' ', md5($raw), ' ', http_build_query($_POST);
