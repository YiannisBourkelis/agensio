<?php
// An application that sends its own HSTS on every page (Rails' force_ssl, Kanboard's ENABLE_HSTS):
// health's probe of / finds it before any visitor came (docs/redirects.md 4.2).
header("Strict-Transport-Security: max-age=63072000; includeSubDomains");
echo "an application with HSTS of its own";
