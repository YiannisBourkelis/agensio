#!/bin/sh
# A header line of 2,000 bytes: past a head_max of 1 KB.
printf 'Content-Type: text/plain\r\nX-Big: '
head -c 2000 /dev/zero | tr '\0' a
printf '\r\n\r\nbig head\n'
