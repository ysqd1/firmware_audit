#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "== semgrep/bin contents now =="
ls /usr/local/lib/python3.11/site-packages/semgrep/bin/ 2>&1
echo "== pip config =="
pip3 config list 2>&1
env | grep -i -E "pip|index" 2>/dev/null
echo "== where did wheel come from (RECORD mtime) =="
stat -c "%y %n" /usr/local/lib/python3.11/site-packages/semgrep/bin/* 2>/dev/null | head -5
echo "== try explicit core check =="
python3.11 -c "import semgrep, os; p=os.path.join(os.path.dirname(semgrep.__file__),'bin'); print(p); print(os.listdir(p)[:8])" 2>&1
echo EXIT_OK
