<?php
header('Content-Type: text/plain');
for ($i = 0; $i < 5; $i++) { echo "chunk$i\n"; flush(); usleep(50000); }
