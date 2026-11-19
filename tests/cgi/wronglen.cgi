#!/bin/sh
# A script that lies about its length: whole and shorter is a 502, longer is cut to it.
# ?huge declares 5 and sends 600,000 bytes (more than the read-ahead holds), whatever the method.
if [ "$QUERY_STRING" = huge ]; then
  printf 'Content-Type: text/plain\r\nContent-Length: 5\r\n\r\n'
  head -c 600000 /dev/zero | tr '\0' x
elif [ "$QUERY_STRING" = long ]; then
  printf 'Content-Type: text/plain\r\nContent-Length: 5\r\n\r\n'
  head -c 100 /dev/zero | tr '\0' x
else
  printf 'Content-Type: text/plain\r\nContent-Length: 100\r\n\r\nshort'
fi
