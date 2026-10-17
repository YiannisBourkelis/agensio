<?php
// docs/headers.md 2.4: an answer that sets a cookie and says nothing to caches; a rule's lifetime at
// /cache/ reaches it private, so no shared cache hands the cookie to the next visitor.
setcookie("sid", "fixture");
echo "an answer with a cookie";
