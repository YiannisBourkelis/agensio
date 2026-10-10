<?php
// Stands in for WordPress's wp-admin/load-styles.php: the login page's concatenated core styles.
header("Content-Type: text/css");
echo "/* load-styles: ", implode(",", (array) ($_GET["load"] ?? [])), " */\n";
