<?php
// docs/headers.md 2.4: an answer with a lifetime of its own, which a rule's set replaces.
header("Cache-Control: max-age=60");
echo "a public page";
