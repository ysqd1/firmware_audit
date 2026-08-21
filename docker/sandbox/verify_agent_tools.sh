#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "== checksec version =="
checksec --version
echo "== cve-bin-tool version =="
cve-bin-tool --version 2>&1 | head -2
echo "== radare2 version =="
r2 -v | head -2
echo "== checksec on /bin/ls =="
checksec --file=/bin/ls 2>&1 | tail -1
echo "== r2 analysis test on /bin/ls =="
r2 -q -A -c 'afl' /bin/ls 2>/dev/null | head -3
echo "== semgrep still ok =="
semgrep --version | head -1
echo "== sfdisk still ok =="
sfdisk --version | head -1
echo EXIT_OK
