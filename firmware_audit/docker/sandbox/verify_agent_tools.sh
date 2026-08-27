#!/bin/bash
# 镜像回归脚本:agent 工具层四工具 + 环境检查 + Ghidra 实跑
# 用法: docker run --rm --entrypoint bash -v <本脚本>:/verify.sh:ro firm_audit/sandbox:<tag> /verify.sh
fail=0
echo "== checksec =="
checksec --version | head -1 && checksec --file=/bin/ls >/dev/null 2>&1 && echo "PASS" || { echo "FAIL"; fail=1; }

echo "== cve-bin-tool =="
cve-bin-tool --version 2>&1 | head -1 && echo "PASS" || { echo "FAIL"; fail=1; }

echo "== radare2 =="
r2 -v | head -1
n=$(r2 -q -A -c 'afl' /bin/ls 2>/dev/null | wc -l)
[ "$n" -gt 5 ] && echo "PASS (afl=$n)" || { echo "FAIL (afl=$n)"; fail=1; }

echo "== semgrep =="
semgrep --version 2>/dev/null | grep -v Warning | head -1
cat > /tmp/rule.yaml <<'EOF'
rules:
  - id: test-os-system
    pattern: os.system(...)
    message: os.system usage
    languages: [python]
    severity: WARNING
EOF
printf 'import os\nos.system(input())\n' > /tmp/t.py
out=$(semgrep --config /tmp/rule.yaml /tmp/t.py --json 2>/dev/null)
cnt=$(echo "$out" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['results']))" 2>/dev/null)
[ "$cnt" = "1" ] && echo "PASS (findings=1)" || { echo "FAIL (findings=$cnt)"; fail=1; }

echo "== java(应指向 jdk-21)=="
java -version 2>&1 | head -1
java -version 2>&1 | grep -q 'version "21' && echo "PASS" || { echo "FAIL"; fail=1; }

echo "== sfdisk(step0 依赖)=="
sfdisk --version | head -1 && echo "PASS" || { echo "FAIL"; fail=1; }

echo "== Ghidra headless 实跑 /bin/ls =="
mkdir -p /tmp/ghp
analyzeHeadless /tmp/ghp RegressProj -import /bin/ls -analysisTimeoutPerFile 60 -deleteProject > /tmp/gh.log 2>&1
if grep -q "Analysis succeeded" /tmp/gh.log; then echo "PASS (Analysis succeeded)"; else echo "FAIL"; tail -5 /tmp/gh.log; fail=1; fi

echo "== 冗余项应已消失(rust/go/gosec/openjdk-11/17)=="
for c in cargo rustc go gosec; do command -v $c >/dev/null 2>&1 && { echo "FAIL: $c still present"; fail=1; }; done
ls /usr/lib/jvm/ 2>/dev/null | grep -E 'java-(11|17)' && { echo "FAIL: jdk 11/17 still present"; fail=1; }
[ ! -e /usr/local/go ] && [ ! -e /usr/local/rustup ] && echo "PASS (all gone)" || { echo "FAIL"; fail=1; }

echo "== pip3 check =="
pip3 check 2>&1 | head -4

echo "== RESULT: $([ $fail -eq 0 ] && echo ALL-PASS || echo HAS-FAIL) =="
exit $fail
