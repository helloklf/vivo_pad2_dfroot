# 对照变体 A / B

这两个构建是实验对照组，**不是可用交付物**，保留供研究参考。
主交付物是上级目录的 `DirtyFrag-fixed-C.apk`。

| 变体 | vermagic flags | __versions | 本设备实测结果 |
|---|---|---|---|
| A（`DirtyFrag-fixed-A.apk`） | 标准 GKI（无 `vivo` token） | 11 条 GKI CRC | 半成功：App 显示成功但 KernelSU 未安装（原因未实锤） |
| B（`DirtyFrag-fixed-B.apk`） | 含 `vivo` token | 11 条 GKI CRC | 直接失败：证明 vivo -dirty 树至少一个符号 CRC 偏离 GKI |

设计意图与结论推导见 [../../docs/technical-writeup.md](../../docs/technical-writeup.md) §6；
制作方法见 [../../docs/reproduction.md](../../docs/reproduction.md)。

校验值见 [../SHA256SUMS](../SHA256SUMS)。
