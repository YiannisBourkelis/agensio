<?php
// docs/headers.md 2.4: what Django's SessionMiddleware sends on a page that read the session, Vary:
// Cookie and no Cache-Control; a rule's lifetime at /cache/ reaches it private.
header("Vary: Cookie");
echo "a page that depends on the visitor's cookie";
