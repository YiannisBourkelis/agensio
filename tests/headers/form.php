<?php
// The form fixture (the alpha.115 report): what PHP parsed of a POST, as
// "content type|fields parsed|accept". Over HTTP/3 a client sends an exact static-table match as
// its index, so this shows the QPACK static table's value as the server decoded it.
echo $_SERVER["CONTENT_TYPE"] ?? "-", "|", count($_POST), "|", $_SERVER["HTTP_ACCEPT"] ?? "-", "\n";
