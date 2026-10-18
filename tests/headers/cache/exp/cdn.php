<?php
// docs/headers.md 2.4: the application tells CDNs not to store (RFC 9213); a rule's Surrogate-Control,
// which Fastly and Varnish read in its place, and its Expires are not added.
header("CDN-Cache-Control: no-store");
echo "an answer CDNs must not store";
