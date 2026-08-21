#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "== ls r2/radare2 =="
ls -la /usr/local/bin/r2 /usr/local/bin/radare2 2>&1
echo "== radare2 -v =="
radare2 -v 2>&1 | head -2
echo "== r2 -v =="
r2 -v 2>&1 | head -2
echo "== axt test on /bin/ls =="
radare2 -q -c 'aa; axt sym.imp.system' /bin/ls 2>/dev/null | head -3
echo EXIT_OK
