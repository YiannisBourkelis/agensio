<?php
// docs/headers.md 2.4: a bare private, under rules sending Expires and Surrogate-Control: neither
// is added (a rule's Expires would give the browser a lifetime the application did not give).
header("Cache-Control: private");
echo "a private answer";
