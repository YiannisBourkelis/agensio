<?php
// docs/headers.md 2.4: Vary: *, which no cache may reuse (RFC 9111 4.1); a rule's lifetime reaches it private.
header("Vary: *");
echo "an answer no cache may reuse";
