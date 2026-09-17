#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'method=%s\npath_info=%s\nquery=%s\nscript=%s\nx_test=%s\ncwd=%s\n' "$REQUEST_METHOD" "$PATH_INFO" "$QUERY_STRING" "$SCRIPT_NAME" "$HTTP_X_TEST" "$(pwd)"
