<?php
// docs/headers.md 2.4: what session_start() sends by default (session.cache_limiter = nocache),
// which a rule's lifetime at /cache/ never replaces.
header("Cache-Control: no-store, no-cache, must-revalidate");
echo "a signed-in visitor's page";
