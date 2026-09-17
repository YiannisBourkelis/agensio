#!/bin/sh
echo "something went sideways" >&2
printf 'Content-Type: text/plain\r\n\r\nok despite stderr\n'
