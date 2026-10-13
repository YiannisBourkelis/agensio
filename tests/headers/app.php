<?php
// The response headers fixture's application (docs/headers.md 2): fields of its own, which the
// site's rules replace (Referrer-Policy), keep (X-Frame-Options, a default) or drop (X-Powered-By).
header("X-Powered-By: AppFramework/1.0");
header("X-Frame-Options: DENY");
header("Referrer-Policy: unsafe-url");
echo "an application with fields of its own";
