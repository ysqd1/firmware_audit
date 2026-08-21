#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "PATH=$PATH"
echo "=== tool check ==="
for c in checksec cve-bin-tool r2 radare2 rabin2 semgrep python3 pip3 file strings readelf objdump sfdisk gcc curl jq; do
  p=$(command -v "$c" 2>/dev/null)
  echo "$c => ${p:-MISSING}"
done
echo "=== pip packages ==="
pip3 list 2>/dev/null | grep -iE 'cve|semgrep|angr|frida|qiling|requests' || echo '(none)'
echo "=== os ==="
cat /etc/os-release | head -2
