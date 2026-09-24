#!/bin/bash
# Profile one agensio worker under h2load (64 connections x 100 streams): the wire shape of
# an answer, syscalls per request, then flat perf profiles on h2c and on h2 over TLS. The
# server runs in the agensio-devbox-perf container (perf, strace), the load generator in a
# second one sharing its network namespace. Arguments: config (one worker, 8080 plain with
# h2c and 8443 TLS), the h2c URL, the TLS URL. Output: the profile text on stdout.
set -u
CFG=${1:-bench/tmp/perf-h2.toml}; URL=${2:-http://127.0.0.1:8080/baseline2?a=1&b=2}; TLSURL=${3:-https://127.0.0.1:8443/baseline2?a=1&b=2}
cd /home/yiannis/projects/agensio
docker rm -f perfbox >/dev/null 2>&1
docker run -d --name perfbox --init --cap-add SYS_ADMIN --cap-add PERFMON --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox-perf sleep 3600 >/dev/null
docker exec -d perfbox bash -c "build/agensio -c $CFG > /tmp/agensio.err 2>&1"
sleep 1
lg() { docker run --rm --network container:perfbox -v "$PWD:$PWD" -w "$PWD" agensio-devbox "$@"; }
echo "== wire (h2c): the frames of two answers on one connection"
lg nghttp -v "$URL" "$URL" 2>&1 | grep -a -E "recv \(stream_id=[0-9]+\) (HEADERS|DATA) frame|^ +:status|^ +(server|date|content-type|content-length):" | sed 's/^\[.*\] //' | head -12
echo "== syscalls (h2c, 3 s under load)"
lg h2load -c 64 -m 100 -t 4 -D 6 "$URL" > bench/tmp/h2load-st.txt 2>&1 &
sleep 1.5; docker exec perfbox bash -c 'P=$(pidof agensio); timeout -s INT 3 strace -c -f -p $P -o /tmp/strace.txt >/dev/null 2>&1; awk "NR<=2 || /total/ || /sendmsg|writev|recvfrom|epoll|write|sendto|read/" /tmp/strace.txt | head -14'
wait
grep -a -E "finished in|requests:" bench/tmp/h2load-st.txt | head -2
echo "== profile (h2c)"
lg h2load -c 64 -m 100 -t 4 -D 8 "$URL" > bench/tmp/h2load-c.txt 2>&1 &
sleep 1.5; docker exec perfbox bash -c 'P=$(pidof agensio); perf record -F 1999 -p $P -o /tmp/perf-h2c.data -- sleep 5 >/dev/null 2>&1; perf report -i /tmp/perf-h2c.data --stdio --no-children --sort symbol 2>/dev/null | grep -E "^ +[0-9]" | head -44'
wait
grep -a -E "finished in" bench/tmp/h2load-c.txt
echo "== profile (h2 over TLS)"
lg h2load -c 64 -m 100 -t 4 -D 8 "$TLSURL" > bench/tmp/h2load-t.txt 2>&1 &
sleep 1.5; docker exec perfbox bash -c 'P=$(pidof agensio); perf record -F 1999 -p $P -o /tmp/perf-h2.data -- sleep 5 >/dev/null 2>&1; perf report -i /tmp/perf-h2.data --stdio --no-children --sort symbol 2>/dev/null | grep -E "^ +[0-9]" | head -30'
wait
grep -a -E "finished in" bench/tmp/h2load-t.txt
docker exec perfbox bash -c 'ps -o cputime= -p $(pidof agensio)'
docker rm -f perfbox >/dev/null
