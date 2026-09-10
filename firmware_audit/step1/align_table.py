"""对齐表:引导解包路由与 binwalk 签名库可解集的对齐声明(票01,基线 binwalk 3.1.1)。

背景(target/4 教训):binwalk 3.1.1 有 72 个可解签名,引导解包器自有识别表只覆盖
其中 18 个——SHRS 加密固件(D-Link DIR-882)被 finalize 留树,解出零内容树,
Step5 空转一整轮(~300 万 token)产出"解包阻塞"空报告。本表把"binwalk 能解而
我们留树"的差距归零,并由漂移守护测试(test_step1_align 的
test_align_table_covers_binwalk_extractable)防止镜像升级后差距重新拉开。

为什么不全交 binwalk(三理由,按权重排序):
1. binwalk v3 的失败方式是**静默成功**——打不开/解不出都 rc=0 空输出(ERROR 在
   stderr;2026-09-10 两度实测),没有"报错"可接;
2. 成本:每次调用一个全新容器;30 万文件级分区(APP 实测)全交 = 30 万容器。
   识别表让判定在 Python 进程内微秒级完成,容器只花在真候选上;
3. fdt 旧疾:binwalk -M 盲解曾把设备树分解成 61.6 万节点——自有识别表 +
   preclassify 硬跳过是治本结构,不回退。

条目粒度只到"交 binwalk":解密/解包由 binwalk 内置 extractor 负责(本表只管
"递过去");binwalk 也解不了的厂商魔数维持 finalize 留树,全树零内容时由 main
零内容守卫终止并明确报"解不了"。不设外部解密命令字段——真出现时立票再议(YAGNI)。

覆盖记账(72 = 18 既有别名 + 34 对齐 + 20 忽略):既有识别表条目经漂移测试的
别名映射计入覆盖;ALIGN_TABLE/IGNORE_LIST 各条目的备注即决策记录。
"""
from __future__ import annotations

# 对齐条目 = (binwalk 签名名, 偏移, 魔数字节, 出处备注)。
# 偏移非 0 表示魔数锚定在文件内固定位置(如 ISO 主卷描述符、UEFI FV 头)。
ALIGN_TABLE: list[tuple[str, int, bytes, str]] = [
    # -- 厂商加密/混淆固件(binwalk 内置解密,对齐的最初动机) --
    ("shrs", 0, b"SHRS",
     "D-Link 私有加密固件(target/4 实测);binwalk ≥3.1 内置解密,"
     "解出 decrypted.bin 后经 uimage/lzma 链继续解"),
    ("arcadyan", 0, b"\x00\xd5\x08\x00",
     "Arcadyan 混淆 LZMA,binwalk 内置去混淆解压"),
    ("autel", 0, b"ECC0101\x00", "Autel 固件"),
    ("csman", 0, b"SC", "csman 固件(2 字节 ASCII 弱魔数,文本误报由空产出留树兜底)"),
    ("csman", 0, b"CS", "csman 固件(同上)"),
    ("dahua_zip", 0, b"DH\x03\x04", "大华 DH 变体 zip"),
    ("dkbs", 0, b"_dkbs_", "DKBS 固件"),
    ("dlink_tlv", 0, b"d\x80\x19@", "D-Link TLV 配置/固件段"),
    ("dlke", 0, b"DLK6E8202001", "D-Link DLK 加密固件"),
    ("dlke", 0, b"DLK6E6110002", "D-Link DLK 加密固件"),
    ("encrpted_img", 0, b"encrpted_img", "厂商加密镜像(ASCII 魔数,源码拼写如此)"),
    ("jboot_sch2", 0, b"$!\x00\x02", "JBOOT SCH2 路由器固件"),
    ("jboot_sch2", 0, b"$!\x01\x02", "JBOOT SCH2 路由器固件"),
    ("jboot_sch2", 0, b"$!\x02\x02", "JBOOT SCH2 路由器固件"),
    ("jboot_sch2", 0, b"$!\x03\x02", "JBOOT SCH2 路由器固件"),
    ("matter_ota", 0, b"\x1e\xf1\xee\x1b", "Matter OTA 固件"),
    ("mh01", 0, b"MH01", "MH01 固件"),
    # -- 固件容器/文件系统 --
    ("android_sparse", 0, b":\xff&\xed", "Android sparse 镜像"),
    ("trx", 0, b"HDR0", "Broadcom TRX 固件容器"),
    ("romfs", 0, b"-rom1fs-", "romfs 文件系统"),
    ("yaffs", 0, b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff",
     "YAFFS/YAFFS2(unyaffs)"),
    ("yaffs", 0, b"\x00\x00\x00\x03\x00\x00\x00\x01\xff\xff",
     "YAFFS/YAFFS2 小端变体(unyaffs)"),
    ("yaffs", 0, b"\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff",
     "YAFFS/YAFFS2 变体(unyaffs)"),
    ("yaffs", 0, b"\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff",
     "YAFFS/YAFFS2 小端变体(unyaffs)"),
    ("qnx_ifs", 0, b"\xeb~\xff\x00\x01\x00", "QNX IFS 文件系统(dumpifs)"),
    ("ntfs", 0, b"\xebR\x90NTFS    ", "NTFS 引导扇区(tsk_recover)"),
    ("uefi_pi_volume", 40, b"_FVH",
     "UEFI PI 卷;_FVH 位于 FV 头偏移 40(UEFI 规范)"),
    ("efigpt", 510, b"\x55\xaaEFI PART",
     "GPT 磁盘;整机镜像由 Step0 分区直读前置处理,此处兜底树内嵌套镜像"),
    ("iso9660", 0x8001, b"\x01CD001\x01\x00",
     "ISO9660 主卷描述符位于扇区 16(偏移 0x8001)"),
    # -- 归档/压缩 --
    ("arj", 0, b"`\xea", "ARJ 归档(2 字节魔数,7zz 解)"),
    ("cab", 0, b"MSCF\x00\x00\x00\x00", "MS CAB 归档(cabextract)"),
    ("rar", 0, b"Rar!\x1a\x07", "RAR 归档(unrar)"),
    ("compressd", 0, b"\x1f\x9d\x90", "compress'd 压缩流(7zz)"),
    ("lzfse", 0, b"bvx-", "Apple LZFSE 压缩"),
    ("lzfse", 0, b"bvx1", "Apple LZFSE 压缩"),
    ("lzfse", 0, b"bvx2", "Apple LZFSE 压缩"),
    ("lzfse", 0, b"bvxn", "Apple LZFSE 压缩"),
    ("lzop", 0, b"\x89LZO\x00\r\n\x1a\n", "LZO 压缩"),
    ("zlib", 0, b"x\x9c", "zlib 流(2 字节 CMF/FLG 弱魔数;压缩流解包是 Step1 本职,"
                          "误报由空产出留树兜底)"),
    ("zlib", 0, b"x\xda", "zlib 流(同上)"),
    ("zlib", 0, b"x^", "zlib 流(同上)"),
    # -- 固件镜像/其他 --
    ("apfs", 0, b"NXSB", "Apple File System(7zz)"),
    ("dms", 0, b"0><1", "DMS 归档"),
    ("pchrom", 0, b"\x5a\xa5\xf0\x0f", "Intel PCH ROM"),
    ("uefi_capsule", 0, b"\xbd\x86f;v\r0@\xb7\x0e\xb5Q\x9e/\xc5\xa0",
     "UEFI Capsule(GUID 魔数,uefi-firmware-parser)"),
    ("uefi_capsule", 0, b"\x8b\xa6<J#w\xfbH\x80=W\x8c\xc1\xfe\xc4M",
     "UEFI Capsule(GUID 魔数)"),
    ("uefi_capsule", 0, b"\xb9\x82\x91S\xb5\xab\x91C\xb6\x9a\xe3\xa9C\xf7/\xcc",
     "UEFI Capsule(GUID 魔数)"),
    ("vxworks_symtab", 0, b"\x00\x00\x05\x00\x00\x00\x00\x00",
     "VxWorks 符号表(type/group 字段,弱魔数,空产出留树兜底)"),
    ("vxworks_symtab", 0, b"\x00\x00\x07\x00\x00\x00\x00\x00", "VxWorks 符号表(同上)"),
    ("vxworks_symtab", 0, b"\x00\x00\x09\x00\x00\x00\x00\x00", "VxWorks 符号表(同上)"),
    ("vxworks_symtab", 0, b"\x00\x05\x00\x00\x00\x00\x00\x00", "VxWorks 符号表(同上)"),
    ("vxworks_symtab", 0, b"\x00\x07\x00\x00\x00\x00\x00\x00", "VxWorks 符号表(同上)"),
    ("vxworks_symtab", 0, b"\x00\x09\x00\x00\x00\x00\x00\x00", "VxWorks 符号表(同上)"),
    ("wince", 0, b"B000FF\n", "Windows CE 镜像"),
]

# 显式忽略清单:(binwalk 签名名, 理由)。可解但决定不路由的签名必须在此登记
# (漂移守护测试强制),理由即决策记录,供后人复核。
IGNORE_LIST: list[tuple[str, str]] = [
    ("dtb", "fdt 设备树:part05 61.6 万节点事故,preclassify 硬跳过,永不解包"),
    ("srecord", "S-record 文本型固件 hex,文本启发式先判 product;转二进制需求与 "
                "ADR-0011 分诊知识同轨,审 MCU blob 时立票再接"),
    ("srecord_generic", "同 srecord(宽松变体)"),
    ("encfw", "魔数为动态固件 ID 表(known_firmware dict),无法静态提取;出现案例再接"),
    ("mbr", "与既有 fat 条目同魔数位(510/55AA),已由 fat 路由到同一提取器"),
    ("dmg", "koly 尾块位于文件末尾,offset-0 锚定不适用"),
    ("linux_kernel", "内核经 uimage/压缩链路路由;vmlinux-to-elf 重且慢"),
    ("bmp", "媒体文件,是审计对象不是容器,解包无意义"),
    ("gif", "媒体文件,同上"),
    ("jpeg", "媒体文件,同上"),
    ("png", "媒体文件,同上"),
    ("svg", "媒体文件(文本型,文本启发式先判 product)"),
    ("riff", "RIFF 容器(wav/avi),审计对象非容器"),
    ("pcapng", "网络抓包,审计对象非容器"),
    ("dxbc", "DirectX 着色器,产品文件非容器"),
    ("pem_certificate", "证书是审计对象(Step5 strings/read_file 直读),不作容器"),
    ("pem_private_key", "私钥是审计对象,不作容器"),
    ("pem_public_key", "公钥是审计对象,不作容器"),
    ("gpg_signed", "GPG 签名材料是审计对象,不作容器"),
    ("openssl", "OpenSSL 签名表弱信号,提取无审计价值"),
]

# 对齐表全部签名名(容器裁决集的消费形态)
ALIGN_NAMES: frozenset[str] = frozenset(name for name, _off, _magic, _note in ALIGN_TABLE)
