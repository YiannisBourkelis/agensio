<?php
// Server-sent events for the compression rows (docs/design-compression.md 6, step 6): five events
// 300 ms apart, each flushed, so a compressed stream must send each one before the next exists.
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
while (ob_get_level() > 0) ob_end_flush();
for ($i = 1; $i <= 5; ++$i) {
    echo "id: $i\nevent: price\ndata: {\"symbol\":\"ABC\",\"price\":" . (100 + $i) . ",\"currency\":\"EUR\"}\n\n";
    flush();
    usleep(300000);
}
