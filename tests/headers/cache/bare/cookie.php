<?php
// docs/headers.md 2.4: a cookie's answer under a rule that removes Cache-Control: left without one
// it would be heuristically cacheable (RFC 9111 4.2.2), so it says private.
setcookie("sid", "fixture");
header("Cache-Control: public, max-age=60");
echo "a cookie's answer";
