#!/bin/sh
printf 'Content-Type: application/octet-stream\r\n\r\n'
head -c 3000000 /dev/zero | tr '\0' 'z'
