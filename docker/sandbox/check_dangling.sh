#!/bin/bash
echo "== dangling symlinks under /usr/local (target in /tmp/radare2) =="
find /usr/local -type l 2>/dev/null | while read -r f; do
  t=$(readlink "$f")
  case "$t" in
    /tmp/radare2/*) echo "$f -> $t" ;;
  esac
done | head -40
echo "== total count =="
find /usr/local -type l 2>/dev/null | while read -r f; do
  t=$(readlink "$f")
  case "$t" in /tmp/radare2/*) echo x ;; esac
done | wc -l
echo "== libr real files check =="
ls -la /usr/local/lib/libr_core.so* /usr/local/lib/libr_bin.so* 2>&1 | head -6
echo EXIT_OK
