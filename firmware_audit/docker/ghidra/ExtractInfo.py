# -*- coding: utf-8 -*-
# ruff: noqa: F821  # getScriptArgs/currentProgram/basestring/unicode 由 Ghidra Jython 环境注入/为 py2 兼容,勿改
# ExtractInfo.py - Ghidra Headless program info extraction script
#
# Purpose: extract decompiled C / functions.json / imports.json / symbols.json
# Usage:   analyzeHeadless <proj> <name> -import <bin> -postScript ExtractInfo.py <output_dir>
#
# Output (under output_dir):
#   decompiled.c       - all functions decompiled C code concatenated
#   functions.json     - function list (name/address/callgraph)
#   imports.json       - external imported symbols
#   symbols.json       - exported symbols
#
# Jython 2.7 syntax (Python 2). All file writes use utf-8 via io.open.

import io
import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def main():
    monitor = ConsoleTaskMonitor()

    args = getScriptArgs()
    if len(args) < 1:
        print("ERROR: ExtractInfo.py needs one arg: output_dir")
        return
    output_dir = args[0]
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    program = currentProgram
    prog_name = program.getName()
    print("ExtractInfo: start processing %s" % prog_name)

    # --- 1. imports (external symbols) ---
    imports = []
    sym_table = program.getSymbolTable()
    ext_symbols = sym_table.getExternalSymbols()
    ref_mgr = program.getReferenceManager()
    while ext_symbols.hasNext():
        sym = ext_symbols.next()
        call_sites = []
        rit = ref_mgr.getReferencesTo(sym.getAddress())
        while rit.hasNext():
            ref = rit.next()
            from_addr = ref.getFromAddress()
            f = program.getFunctionManager().getFunctionContaining(from_addr)
            call_sites.append({
                "from": str(from_addr),
                "function": f.getName() if f is not None else "",
            })
        imports.append({
            "name": sym.getName(),
            "parent": str(sym.getParentNamespace()),
            "address": str(sym.getAddress()),
            "ref_count": sym.getReferenceCount(),
            "call_sites": call_sites,
        })
    _write_json(output_dir, "imports.json", imports)
    print("ExtractInfo: imports=%d" % len(imports))

    # --- 2. symbols (exported/global, skip locals) ---
    symbols = []
    sym_iter = sym_table.getSymbolIterator()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.isExternal():
            continue
        sym_type = str(sym.getSymbolType())
        if sym_type in ("Function", "Label", "Class", "Namespace"):
            symbols.append({
                "name": sym.getName(),
                "address": str(sym.getAddress()),
                "type": sym_type,
                "parent": str(sym.getParentNamespace()),
            })
    _write_json(output_dir, "symbols.json", symbols)
    print("ExtractInfo: symbols=%d" % len(symbols))

    # --- 3. init decompiler ---
    decomp = DecompInterface()
    decomp.openProgram(program)

    # --- 4. functions + decompiled C ---
    func_manager = program.getFunctionManager()
    functions = []
    decompiled_chunks = []
    decompiled_count = 0
    failed_count = 0
    total_funcs = 0

    func_iter = func_manager.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        total_funcs += 1
        entry = func.getEntryPoint()
        name = func.getName()
        addr_str = str(entry)

        # Skip EXTERNAL/thunk functions to avoid pcode warnings
        if func.isExternal() or func.isThunk():
            continue

        callees = []
        for called in func.getCalledFunctions(monitor):
            callees.append(called.getName())
        callers = []
        for caller in func.getCallingFunctions(monitor):
            callers.append(caller.getName())

        decomp_result = decomp.decompileFunction(func, 60, monitor)
        c_code = ""
        if decomp_result and decomp_result.decompileCompleted():
            df = decomp_result.getDecompiledFunction()
            if df is not None:
                c_code = df.getC()
                decompiled_count += 1
            else:
                c_code = "// decompile returned null: %s @ %s" % (name, addr_str)
                failed_count += 1
        else:
            c_code = "// decompile failed: %s @ %s" % (name, addr_str)
            failed_count += 1

        decompiled_chunks.append(
            u"// ===== Function: %s @ %s =====\n%s\n" % (name, addr_str, c_code)
        )

        functions.append({
            "name": name,
            "address": addr_str,
            "size": func.getBody().getNumAddresses(),
            "param_count": func.getParameterCount(),
            "callees": callees,
            "callers": callers,
        })

    decomp.dispose()

    # write decompiled.c (utf-8)
    c_path = os.path.join(output_dir, "decompiled.c")
    header = (
        u"// decompiled output - %s\n"
        u"// extractinfo_version: 2\n"  # 产物格式版本;step4 校验,旧版自动失效重跑
        u"// decompile_success: %d\n"  # machine-readable: N>0 才算反编译真正成功
        u"// total functions: %d, success: %d, failed: %d\n"
        u"// generated by Ghidra ExtractInfo.py\n\n"
    ) % (prog_name, decompiled_count, total_funcs, decompiled_count, failed_count)
    with io.open(c_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(u"\n".join(decompiled_chunks))
    print("ExtractInfo: decompiled.c written (%d/%d success)" % (decompiled_count, total_funcs))

    _write_json(output_dir, "functions.json", functions)
    print("ExtractInfo: functions=%d" % len(functions))

    # --- 5. strings with refs (hardcoded credential goldmine) ---
    strings = []
    # Jython 环境把 getDefinedData(True) 的数据项暴露为底层实现类 DataDB,
    # 无公开 Data 接口的 isString() 方法(实测 AttributeError)。而字符串数据项的
    # getValue() 在 Jython 里直接返回解码后的 unicode 字符串(实测),非字符串数据
    # 返回其他类型,故用 isinstance(..., basestring) 过滤即可,兼容任何 Ghidra 版本。
    str_iter = program.getListing().getDefinedData(True)
    string_ref_mgr = program.getReferenceManager()
    func_mgr = program.getFunctionManager()
    while str_iter.hasNext():
        data = str_iter.next()
        value = data.getValue()   # 字符串数据 -> unicode 字符串;非字符串 -> 其他类型
        if not isinstance(value, basestring):
            continue
        addr = data.getAddress()
        value_str = unicode(value)[:200]   # 值截断 200 字符,防文件过大
        refs = []
        rit = string_ref_mgr.getReferencesTo(addr)
        ref_count = 0
        while rit.hasNext() and ref_count < 20:   # 每字符串最多记 20 条引用,防膨胀
            ref = rit.next()
            from_addr = ref.getFromAddress()
            f = func_mgr.getFunctionContaining(from_addr)
            refs.append({
                "from": str(from_addr),
                "function": f.getName() if f is not None else "",
            })
            ref_count += 1
        strings.append({
            "address": str(addr),
            "value": value_str,
            "length": data.getLength(),   # 数据项长度 = 字符串在文件中的字节数
            "refs": refs,
        })
    _write_json(output_dir, "strings.json", {"version": 2, "program": prog_name, "strings": strings})
    print("ExtractInfo: strings=%d" % len(strings))

    # --- 6. program meta ---
    lang = program.getLanguage()
    entry_iter = program.getSymbolTable().getExternalEntryPointIterator()
    entries = []
    while entry_iter.hasNext():
        entries.append(str(entry_iter.next()))
    meta = {
        "version": 2,
        "program": prog_name,
        "language": {
            "processor": lang.getProcessor().toString(),
            "endian": "big" if lang.isBigEndian() else "little",
            "address_size": lang.getDefaultSpace().getPointerSize(),
        },
        "compiler": program.getCompilerSpec().toString(),
        "md5": program.getExecutableMD5(),
        "sha256": program.getExecutableSHA256(),
        "entry_points": entries,
    }
    _write_json(output_dir, "meta.json", meta)

    print("ExtractInfo: done -> %s" % output_dir)


def _write_json(output_dir, filename, data):
    path = os.path.join(output_dir, filename)
    with io.open(path, "w", encoding="utf-8") as f:
        # json.dump in Py2 returns str (ascii); ensure_unicode to make it safe for io.open
        s = json.dumps(data, indent=2, ensure_ascii=True)
        f.write(unicode(s))


main()
