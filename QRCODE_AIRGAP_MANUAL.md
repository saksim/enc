# QRCode OCR 空口传输手册

## 1. 这份手册解决什么问题

`qrcode_helper.py` 不是源码加密器，它是“空口传输层”。

它负责四件事：

1. 把小体积二进制产物导出成适合 OCR / 截图 / 拍照传输的页面包。
2. 从图片中提取 OCR 文本，或者直接读取 `pages_txt/` 文本页。
3. 在恢复前分析 OCR 质量，找出缺页、缺块、冲突和重拍点。
4. 校验并恢复原始字节文件。

它不负责：

1. 源码保护
2. 保密加密
3. Cython 编译

其中：

1. 源码保护属于 `encryption_helper.py`
2. 编译属于 `py2_linux_rec_opera.py`
3. 如果你关心内容保密，应该先自行加密，再交给 `qrcode_helper.py`

## 1.1 能不能直接处理原始文件，比如 `.rar`、`.py`

可以，技术上没有限制。

原因很直接：

1. `export` 实际做的是“读取输入文件原始字节 -> zlib 压缩 -> safe_base32 编码 -> 分块分页”
2. 它不会检查文件类型
3. 它也不会判断文件是否已经加密

这意味着：

1. 你可以直接对原始 `.rar`
2. 你也可以直接对原始 `.py`
3. 你甚至可以对任意其他二进制文件导出

但要分清两个层面：

1. 技术上能导出
2. 安全上是否应该这样做

如果你直接导出原始 `.py` 或未加密的 `.rar`，那么：

1. `qrcode_helper.py` 只是在“搬运字节”
2. 它没有给你的内容增加保密性
3. 拿到页面包、OCR 文本、`payload.txt`、或最终恢复结果的人，理论上都可以还原原文件

所以正确理解应该是：

1. 如果你只是想跨环境搬运文件，可以直接对原始文件导出
2. 如果你还要求保密，必须先加密，再把加密后的产物交给 `qrcode_helper.py`
3. 对 Python 源码场景，通常应该先走 `encryption_helper.py`，再考虑是否要走 OCR 空口传输

## 2. 整体流程

标准链路如下：

1. `export`
2. `ocr-extract`，如果你手里是图片
3. `analyze`
4. `verify`
5. `recover`

如果你想一步走完图片恢复，可以直接用：

1. `recover-images`

## 3. 导出后的目录结构

`export` 成功后，输出目录通常如下：

```text
<output_dir>/
  <ARTIFACT_ID>.manifest.json
  <ARTIFACT_ID>.payload.txt
  pages/
    page_0001.png
    page_0002.png
    ...
  pages_txt/
    page_0001.txt
    page_0002.txt
    ...
```

说明：

1. `manifest.json` 是恢复总索引。
2. `payload.txt` 是完整编码后的原始载荷文本。
3. `pages/` 是图片页，适合截图、相机、跨机传输。
4. `pages_txt/` 是文本页，适合本地 smoke test 或无 OCR 环境。

## 4. 依赖与后端

### 4.1 最低依赖

如果你只想走文本页恢复，或者走 `sidecar` 恢复，最低只要：

```text
Python 3.6+
Pillow
```

例如：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install pillow
```

### 4.2 OCR 依赖

如果你要用 `tesseract` 或 `easyocr`：

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' -m pip install pillow pytesseract easyocr
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install pillow pytesseract
```

### 4.3 后端选择逻辑

可选后端：

1. `sidecar`
2. `tesseract`
3. `easyocr`
4. `auto`

实际建议：

1. `sidecar` 最稳，不依赖文本 OCR 识别，优先用于本工具自己导出的页面。
2. `tesseract` 既可以走 `pytesseract`，也可以直接调用本机 `tesseract.exe`。
3. `easyocr` 更适合 `py311`。
4. `recover-images --backend auto` 会优先试 `sidecar`，然后再试 `tesseract` 和 `easyocr`。

## 5. 命令总览

当前 CLI 子命令有：

1. `export`
2. `estimate`
3. `ocr-extract`
4. `analyze`
5. `verify`
6. `recover`
7. `recover-images`

## 5.2 `estimate` 预估命令

如果你不想反复盲试参数，先跑 `estimate`。

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py estimate `
  -i .\final_try.rar `
  --chunk-chars 40 `
  --lines-per-page 80 `
  --max-compressed-kib 512
```

它不会生成任何文件，只会告诉你：

1. 原始大小
2. 压缩后大小
3. 当前上限是否足够
4. 至少需要多大的 `--max-compressed-kib`
5. 数据块数量
6. parity 块数量
7. 总传输行数
8. 预计总页数
9. 风险提示

例如对你当前的 `final_try.rar`，实测结果是：

1. `compressed_size = 48708`
2. `fits_current_limit = true`
3. `minimum_recommended_max_compressed_kib = 48`
4. `estimated_total_pages = 25`
5. 当前风险提示是：
   - `--lines-per-page 80` 太密
   - 你没开 redundancy，也没开 parity，单页 OCR 损坏就可能卡死恢复

## 5.1 完全不能带 manifest 的场景

如果你的真实约束是：

1. 内网机器只能导出页面
2. 外网机器只能拿到拍照后的图片
3. `manifest.json` 根本带不出来

那么现在支持两种恢复模式：

1. 强校验模式
   - 外网机器有 `manifest.json`
   - 可以做完整 SHA 校验、体积校验、parity 恢复
2. 无 manifest 恢复模式
   - 外网机器没有 `manifest.json`
   - 新版导出页会在每页重复嵌入关键元信息
   - 先从图片提取 `ocr_raw.txt`
   - 再直接基于 `ocr_raw.txt` 恢复原始文件

两者的区别很重要：

1. 有 manifest
   - 最稳
   - 能做完整端到端校验
   - 能利用 parity 做缺块恢复
2. 无 manifest
   - 对新版导出页，可以基于页内元信息做强恢复
   - 可以做压缩包 SHA 校验、原始字节 SHA 校验、原始大小校验
   - 可以重建 parity 组信息并做缺块恢复
   - 只有在页内元信息不完整时，才会退化成结构恢复

所以，不能带 manifest 并不意味着完全不能恢复。对于新版导出页，它已经是可用的强恢复链；只有老页或 OCR 丢失元信息时，才会退化。

## 6. `export` 全参数说明

基础用法：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\encrypted_payload.bin `
  -o .\airgap_pkg
```

### 6.1 参数表

1. `-i`, `--input-file`
   - 必填
   - 含义：输入文件路径，可以是任意二进制文件
   - 注意：如果你关心保密，请先加密，再传给它
2. `-o`, `--output-dir`
   - 必填
   - 含义：输出包目录
3. `--artifact-id`
   - 可选
   - 默认：自动生成
   - 含义：自定义产物 ID
4. `--filename-prefix`
   - 可选
   - 默认：`page`
   - 含义：输出图片 / 文本页文件名前缀
5. `--max-compressed-kib`
   - 可选
   - 默认：`64`
   - 含义：压缩后体积上限，单位 KiB
6. `--chunk-chars`
   - 可选
   - 默认：`40`
   - 含义：每个数据块的字符长度
7. `--lines-per-page`
   - 可选
   - 默认：`20`
   - 含义：每页承载多少个传输行
8. `--redundancy-copies`
   - 可选
   - 默认：`1`
   - 含义：每个块复制多少份
9. `--no-interleave`
   - 可选
   - 默认：不开启此参数，也就是默认交错排布
   - 含义：关闭副本交错
10. `--parity-group-size`
    - 可选
    - 默认：`0`
    - 含义：每 N 个数据块额外生成 1 个 parity 块

### 6.2 每个参数的实际影响

1. `--max-compressed-kib`
   - 决定“压缩后的二进制”是否允许导出。
   - 不是原文件大小限制，而是 `zlib.compress(raw, 9)` 之后的大小限制。
2. `--chunk-chars`
   - 越大，块数越少，页数通常越少。
   - 但每行更长，OCR 更容易出错。
3. `--lines-per-page`
   - 越大，页数越少。
   - 但单页更密，图片更难拍清楚。
4. `--redundancy-copies`
   - 越大，页数越多。
   - 但抗漏拍、抗 OCR 掉字更强。
5. `--no-interleave`
   - 默认不建议开。
   - 交错排布能把重复副本摊开到不同页，单页损坏时恢复率更高。
6. `--parity-group-size`
   - 大于 `1` 才会真正启用 parity。
   - 每组最多可以补回 1 个缺失块。
   - 组越小，抗丢失更强，但页数也会更多。

## 7. `ocr-extract` 全参数说明

基础用法：

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py ocr-extract `
  -i .\airgap_pkg\pages `
  -o .\airgap_pkg\ocr_raw.txt `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  --backend sidecar
```

参数说明：

1. `-i`, `--image-input`
   - 必填
   - 含义：单张图片路径，或图片目录路径
2. `-o`, `--output-text`
   - 必填
   - 含义：OCR 文本输出路径
3. `-m`, `--manifest`
   - 可选
   - 含义：manifest 路径
   - 强烈建议：如果图片是本工具导出的，请一定传
4. `--backend`
   - 可选
   - 默认：`tesseract`
   - 可选值：`tesseract`、`easyocr`、`sidecar`、`auto`
5. `--lang`
   - 可选
   - 默认：`eng`
   - 含义：OCR 语言参数
6. `--psm`
   - 可选
   - 默认：`6`
   - 含义：Tesseract 的页面分割模式

实际建议：

1. 自己导出的页面，优先 `sidecar`。
2. 现在即使没有 `manifest`，新版导出页也会先尝试读取页内嵌元信息，再走结构化提取。
3. `--backend auto` 会优先试无 manifest 结构化提取，再退回普通 OCR。
4. `--manifest` 一旦提供，`sidecar` 和结构化 OCR 的恢复率仍然最高。
5. 老包没有 sidecar 或没有嵌入元信息时，再退回普通 `tesseract` / `easyocr`。

## 8. `analyze` 全参数说明

基础用法：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py analyze `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt `
  --save-report .\airgap_pkg\analyze_report.json `
  --emit-missing-file .\airgap_pkg\missing_chunks.csv
```

参数说明：

1. `-m`, `--manifest`
   - 必填
2. `-t`, `--ocr-input`
   - 必填
   - 含义：OCR 文本文件，或者 `pages_txt/` 目录
3. `--strict-payload-chars`
   - 可选
   - 默认：关闭
   - 含义：严格字符校验，不做宽松纠错
4. `--max-list`
   - 可选
   - 默认：`200`
   - 含义：结果列表最大输出条数
5. `--save-report`
   - 可选
   - 含义：把分析结果落成 JSON
6. `--emit-missing-file`
   - 可选
   - 含义：导出缺块重拍清单 CSV

### 8.1 `analyze` 结果字段怎么读

重点字段：

1. `expected_total_chunks`
   - 理论需要的数据块数量
2. `received_unique_chunks`
   - 已收到的数据块数量
   - 这里只统计数据块，不统计 parity
3. `received_parity_chunks`
   - 已收到的 parity 块数量
4. `missing_chunks_count`
   - 还缺多少数据块
5. `missing_chunk_locations_sample`
   - 缺块可能位于哪些 `page,line,copy`
6. `missing_chunk_retake_plan_sample`
   - 最值得优先重拍的位置
7. `line_error_count`
   - 行级硬错误
8. `line_warning_count`
   - 行级警告
9. `page_crc_error_count`
   - 页面 CRC 警告
10. `duplicate_conflict_count`
    - 同一个块出现冲突

成功判定逻辑：

1. 缺块为 0
2. 行错误为 0
3. 冲突为 0

补充说明：

1. `page_crc_error_count > 0` 只是警告，不一定阻止恢复。
2. 现在 `received_unique_chunks` 和 `received_parity_chunks` 已彻底分离，避免把 parity 误算成数据块。

## 9. `verify` 与 `recover` 全参数说明

### 9.1 `verify`

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py verify `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt
```

参数：

1. `-m`, `--manifest`
2. `-t`, `--ocr-input`
3. `--strict-payload-chars`

无 manifest 用法：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py verify `
  -t .\airgap_demo\ocr_raw.txt
```

说明：

1. 对新版导出页，它会优先使用页内嵌的元信息做强校验。
2. 能校验压缩包 SHA、原始字节 SHA、原始大小。
3. 如果 OCR 丢了这些元信息，才会退化成结构校验。

### 9.2 `recover`

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py recover `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt `
  -o .\recovered_payload.bin
```

参数：

1. `-m`, `--manifest`
2. `-t`, `--ocr-input`
3. `-o`, `--output-file`
4. `--strict-payload-chars`

无 manifest 用法：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py recover `
  -t .\airgap_demo\ocr_raw.txt `
  -o .\airgap_demo\final_try_restored.rar
```

关于 `--strict-payload-chars`：

1. 默认不建议开启，宽松模式更适合真实 OCR 噪声环境。
2. 如果你怀疑 OCR 被错误纠正掩盖，想尽早暴露污染，再开启它。

无 manifest 恢复的限制：

1. 对新版导出页，通常可以做到和 manifest 接近的强恢复。
2. 但它仍然拿不到 `chunk_locations`，所以缺块重拍定位不如 manifest 模式精细。
3. 如果页内嵌元信息被 OCR 丢失，恢复会退化为结构性恢复。

## 10. `recover-images` 全参数说明

基础用法：

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py recover-images `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -i .\airgap_pkg\pages `
  -o .\recovered_payload.bin `
  --backend auto `
  --ocr-text-output .\airgap_pkg\ocr_raw.txt `
  --save-analyze-report .\airgap_pkg\analyze_report.json `
  --emit-missing-file .\airgap_pkg\missing_chunks.csv
```

参数说明：

1. `-m`, `--manifest`
   - 必填
2. `-i`, `--image-input`
   - 必填
   - 图片文件或目录
3. `-o`, `--output-file`
   - 必填
4. `--backend`
   - 默认：`auto`
   - 可选：`tesseract`、`easyocr`、`sidecar`、`auto`
5. `--lang`
   - 默认：`eng`
6. `--psm`
   - 默认：`6`
7. `--strict-payload-chars`
   - 默认：关闭
8. `--ocr-text-output`
   - 可选
   - 指定 OCR 文本落盘位置
9. `--save-analyze-report`
   - 可选
   - 指定分析报告落盘位置
10. `--emit-missing-file`
    - 可选
    - 指定缺块清单 CSV 落盘位置
11. `--max-list`
    - 默认：`200`
    - 控制分析输出列表长度

## 11. 页数、稳定性、体积三者怎么取舍

你真正要平衡的是三件事：

1. 页数
2. OCR 成功率
3. 恢复冗余度

下面是核心规律：

1. `chunk_chars` 越大，页数越少，但 OCR 更难。
2. `lines_per_page` 越大，页数越少，但单页更密，拍照更难。
3. `redundancy_copies` 越大，页数越多，但抗丢失更强。
4. `parity_group-size` 越小，容错越强，但页数也会增加。

一个粗略估算公式：

1. 数据块数约等于 `ceil(编码后总字符数 / chunk_chars)`
2. parity 块数约等于 `ceil(数据块数 / parity_group_size)`，前提是 `parity_group_size > 1`
3. 传输总行数约等于 `(数据块数 + parity块数) * redundancy_copies`
4. 页数约等于 `ceil(传输总行数 / lines_per_page)`

## 12. 不同场景的推荐参数

### 12.1 你刚遇到的场景：文件太大，报体积超限

你的报错：

```text
compressed artifact 367062 bytes exceeds limit 65536 bytes
```

这说明：

1. 不是原文件太大
2. 是压缩后的体积 `367062 bytes`
3. 默认上限 `64 KiB` 不够

最直接的做法：

```bash
/d/code_environment/anaconda_all_css/py36/python ./qrcode_helper.py export \
  -i ./final_try.rar -o ./airgap_demo --filename-prefix demo \
  --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 \
  --parity-group-size 4 --max-compressed-kib 512
```

取值建议：

1. 想只够用，最小值至少要大于 `367062 / 1024`，也就是大约 `359`
2. 实际建议直接给 `384` 或 `512`
3. 如果你预期还会继续变大，直接用 `1024`

何时不该继续拉大：

1. 如果你发现页数已经夸张到不适合拍照
2. 如果你是要人工相机搬运，不是纯文本搬运

这时更好的办法是：

1. 把大文件拆成多个小分卷
2. 每个分卷单独 `export`

### 12.2 想少页数，多放文字

目标：

1. 减少页数
2. 提高单页承载量

建议参数：

```text
--chunk-chars 48 或 64
--lines-per-page 20 到 32
--redundancy-copies 1
--parity-group-size 0 或 8
```

适用场景：

1. 本地直接用 `pages_txt/`
2. 图片非常清晰
3. 不是靠手机随手拍

代价：

1. OCR 误识率会上升
2. 单页太密时，重拍成本反而变高

### 12.3 想提高成功率，宁可多几页

目标：

1. 减少重拍
2. 提高容错

建议参数：

```text
--chunk-chars 24 到 32
--lines-per-page 8 到 12
--redundancy-copies 2
--parity-group-size 4 或 8
```

适用场景：

1. 相机拍照
2. OCR 环境一般
3. 不能保证每页都清晰

### 12.4 想尽量省页，但仍保留一点容错

建议参数：

```text
--chunk-chars 40 到 48
--lines-per-page 16 到 24
--redundancy-copies 1
--parity-group-size 8
```

这是比较折中的一档。

### 12.5 没装 OCR 依赖，想先把链跑通

建议：

1. 直接对 `pages_txt/` 跑 `analyze -> verify -> recover`
2. 或者用 `recover-images --backend auto`，让它优先走 `sidecar`

### 12.6 OCR 很脏，想看最详细的诊断

建议：

```text
--save-report
--emit-missing-file
--max-list 500
```

这样你能得到：

1. JSON 分析报告
2. 缺块 CSV
3. 更长的错误列表

### 12.7 想让“识别错误尽早暴露”，而不是靠宽松模式混过去

在 `analyze`、`verify`、`recover`、`recover-images` 上开启：

```text
--strict-payload-chars
```

适合：

1. 调试
2. 排查 OCR 被误纠正的问题
3. 对错误零容忍的场景

不适合：

1. 正常拍照 OCR 噪声环境

## 13. 推荐起步模板

### 13.1 稳妥模板，适合大多数拍照场景

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\payload.bin `
  -o .\airgap_pkg `
  --chunk-chars 24 `
  --lines-per-page 8 `
  --redundancy-copies 2 `
  --parity-group-size 4 `
  --max-compressed-kib 512
```

### 13.2 省页模板，适合文本页或高质量截图

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\payload.bin `
  -o .\airgap_pkg `
  --chunk-chars 48 `
  --lines-per-page 24 `
  --redundancy-copies 1 `
  --parity-group-size 8 `
  --max-compressed-kib 512
```

### 13.3 低依赖恢复模板

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py analyze `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\pages_txt

& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py verify `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\pages_txt

& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py recover `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\pages_txt `
  -o .\restored.bin
```

### 13.4 纯照片出域，无 manifest 恢复模板

假设外网机器上只有：

1. `./airgap_demo/pages/` 里的照片
2. 没有 `manifest.json`

先提取 OCR 文本：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py ocr-extract `
  -i .\airgap_demo\pages `
  -o .\airgap_demo\ocr_raw.txt `
  --backend tesseract
```

再做校验：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py verify `
  -t .\airgap_demo\ocr_raw.txt
```

最后恢复原始文件：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py recover `
  -t .\airgap_demo\ocr_raw.txt `
  -o .\airgap_demo\final_try_restored.rar
```

这个模板最适合：

1. 完全不能把 `manifest.json` 带出来
2. 你使用的是新版导出页
3. 你希望只靠照片和 OCR 文本恢复原始文件

## 14. 已验证状态

截至 `2026-04-26`，已验证：

1. `py36`
   - `export -> analyze -> verify -> recover` 实机通过
2. `py311`
   - `recover-images --backend auto` 实机通过
   - 自动选择 `sidecar`
3. 当前回归
   - `pytest`：`12 passed`
   - `py36 unittest`：`OK (skipped=7)`

## 15. 最后建议

如果你是第一次真正搬大文件，顺序建议是：

1. 先确定 `--max-compressed-kib` 足够
2. 再决定你是要“少页”还是“稳”
3. 真要拍照传输，优先选稳，不要贪少页
4. 如果页数已经多到难以操作，别硬撑，直接拆分文件

## 16. OCR 低识别率强化（2026-04 更新）

这一版新增了三项直接针对“拍照 OCR 误识率高”的能力：

1. 动态大字体渲染。
`export` 生成 PNG 时会在当前页可容纳的前提下自动放大内容字体；当你降低 `--lines-per-page` 时，内容区字体会更大。

2. 页内控制信息压缩。
每页嵌入元信息从 5 行压缩为 3 行：`@CFG` + `@HS1` + `@HS2`。旧格式 `@RH1/@RH2/@CH1/@CH2` 仍然兼容。

3. 统一 OCR Provider 接口。
`ocr-extract` 与 `recover-images` 支持 `--backend external` + `--ocr-provider-cmd`，可以接入外部 OCR/大模型。

### 16.1 先保识别率的导出模板

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\payload.bin `
  -o .\airgap_pkg `
  --chunk-chars 24 `
  --lines-per-page 8 `
  --redundancy-copies 2 `
  --parity-group-size 4 `
  --max-compressed-kib 512
```

建议：

1. `--lines-per-page` 降低后，字体会自动变大。
2. `--chunk-chars` 控制在 24~32，避免单行太长。
3. 同时开启 redundancy 与 parity 提高容错。

### 16.2 external OCR 统一接口

`ocr-extract` 额外参数：

1. `--backend external`
2. `--ocr-provider-cmd "<命令模板>"`
3. `--ocr-provider-timeout-sec <秒>`

可用占位符：

1. `{image_path}`
2. `{image_name}`
3. `{page_no}`
4. `{lang}`
5. `{psm}`
6. `{manifest_path}`

示例：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py ocr-extract `
  -i .\airgap_pkg\pages `
  -o .\airgap_pkg\ocr_raw.txt `
  --backend external `
  --ocr-provider-cmd "my_ocr_runner --image \"{image_path}\" --page {page_no}" `
  --ocr-provider-timeout-sec 180
```

外部命令输出约定（任一即可）：

1. `stdout` 直接输出 OCR 文本。
2. `stdout` 输出 JSON：`{"text":"..."}` 或 `{"lines":["...","..."]}`。
3. `stdout` 输出 JSON：`{"output_text_path":"..."}`，工具会读取该文件。

### 16.3 recover-images 一步接入 external OCR

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py recover-images `
  -i .\airgap_pkg\pages `
  -o .\restored.bin `
  --backend external `
  --ocr-provider-cmd "my_ocr_runner --image \"{image_path}\" --page {page_no}" `
  --ocr-provider-timeout-sec 180 `
  --ocr-text-output .\airgap_pkg\ocr_raw.txt `
  --save-analyze-report .\airgap_pkg\analyze_report.json `
  --emit-missing-file .\airgap_pkg\missing_chunks.csv
```

如果你希望“外部失败后自动回退”，使用：

```text
--backend auto --ocr-provider-cmd "<命令模板>"
```

## 17. 用户可控开关（字体 / 元信息 / 分隔符）

这组参数用于直接控制你关心的三件事：

1. 字体大小
2. 每页无关信息占比
3. 字段分隔符

### 17.1 字体控制参数

`export` 新增：

1. `--font-size`：基础字体大小（默认 44）
2. `--font-max-size`：仅在 `--font-fit-mode fit` 下生效（默认 132）
3. `--font-fit-mode`：字号策略（`target|fit|fixed`，默认 `target`）
4. `--fixed-font-size`：`--font-fit-mode fixed` 的兼容别名

推荐：

1. 想“严格可控”：用 `--font-fit-mode target`（默认）或 `--font-fit-mode fixed`。
2. 想“尽量铺满页面”：用 `--font-fit-mode fit` + `--font-max-size`。

示例：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\final_try.rar `
  -o .\airgap_demo `
  --font-size 56 `
  --font-max-size 80 `
  --font-fit-mode target
```

说明：

1. `target`：尽量使用 `--font-size`；只有放不下才缩小。
2. `fit`：会自动放大到不超过 `--font-max-size` 的最大可容纳字号。
3. `fixed`：严格使用 `--font-size`，即使可能超出页面。

### 17.2 页内元信息开关

`export` 新增：`--metadata-level`

1. `compact`（默认）：保留控制信息（`@META/@CFG/@HS/@PAGECRC`）
2. `none`：只导出数据行（去掉页头/页尾/控制行）

你要的“页头页尾都不要”就是：

```text
--metadata-level none
```

风险提示：

1. `none` 模式下，诊断能力会下降（无 page CRC / 无页级元信息）。
2. 无 manifest 时会退化为结构恢复，建议同时提高 redundancy/parity 或保持 manifest 可用。

### 17.3 行分隔符开关

`export` 新增：`--line-separator`

可选值：

1. `|`
2. `$`
3. `@`

示例（按你建议改成 `$`）：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\final_try.rar `
  -o .\airgap_demo `
  --metadata-level none `
  --line-separator '$'
```

对应数据行形式：

```text
P001L001$C00000$RDPAAJLA549XE2MUEEPAQAJA9C36NA$2F5E
```

### 17.4 低误识率实战模板（你这个场景）

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\final_try.rar `
  -o .\airgap_demo `
  --chunk-chars 24 `
  --lines-per-page 8 `
  --redundancy-copies 2 `
  --parity-group-size 4 `
  --metadata-level none `
  --line-separator '$' `
  --font-size 56 `
  --font-max-size 88 `
  --font-fit-mode target `
  --max-compressed-kib 512
```

### 17.5 去掉每行 CRC 和右侧点阵（你这次诉求）

两个开关：

1. `--line-crc-mode off`：每行不再追加末尾 CRC 字段。
2. `--no-sidecar`：PNG 右侧不再绘制 sidecar 点阵块。

示例：

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\final_try.rar `
  -o .\airgap_demo `
  --metadata-level none `
  --line-separator '$' `
  --line-crc-mode off `
  --no-sidecar `
  --font-size 56 `
  --font-fit-mode fixed
```

输出行会变成：

```text
P001L001$C00000$RDPAAJLA549XE2MUEEPAQAJA9C36NA
```

### 17.6 页号/行号 OCR 混淆自动归一（新）

在 `ocr-extract / verify / recover / analyze` 解析数据行时，`Pxxx/Lxxx` 会做更激进归一：

1. `0` 类：`0/O/Q/D/@/G/C` 统一按 `0` 处理。
2. `1` 类：`1/I/L` 统一按 `1` 处理。
3. `4` 类：`4/H/M` 统一按 `4` 处理。

说明：

1. 这组归一只针对 `page/line` 前缀，不会改变 `chunk_idx` 的主归一策略（避免把真实 `6` 大量误判成 `0`）。
2. 该能力用于降低 `P001` 被识别成 `POO1/PGG1`、`L004` 被识别成 `L00H` 时的解析失败概率。

### 17.7 行前缀精简开关（可去掉 `P/L/C`）

`export` 新增：`--line-index-mode`

1. `full`（默认）：保留 `PxxxLxxx + Cxxxxx + payload`。
2. `chunk`：保留 `Cxxxxx + payload`（去掉 `P/L`）。
3. `off`：仅保留 `payload`（同时去掉 `P/L/C`）。

示例（`chunk` 模式）：

```text
C00000$RDPAAJLA549XE2MUEEPAQAJA9C36NA
```

示例（`off` 模式）：

```text
RDPAAJLA549XE2MUEEPAQAJA9C36NA
```

注意：

1. `--line-index-mode off` 必须配合 `--no-sidecar`。
2. `off` 模式下，`verify/recover` 无法在“没有 manifest”的情况下推断总块数；必须提供 `manifest.json`。
3. `chunk` 模式下，解析器会对前缀做额外归一：`C` 被 OCR 误读为 `G/Q/O/D/@` 时会自动回归为 `C` 再解析。

### 17.8 “全部归一化”的边界说明（重要）

你提到“把所有相似字符都归一到同一类”。这对**索引字段**可行，但对**payload 字段**不能盲目硬归一，否则会丢失真实信息。

当前策略是：

1. 索引字段（`P/L/C + 数字`）做强归一，优先保障可解析性。
2. payload 使用安全字母表（已避开 `I/O/0/1`）并做保守归一（如 `O/0 -> Q`、`I/1 -> L`）。
3. 通过每行 CRC 进行冲突裁决与纠错（包含常见混淆对：`2/Z`、`4/H`、`5/S`、`6/G`、`7/T`、`8/B`）。

建议：

1. 要降误判，又不丢恢复能力，优先用 `--line-index-mode chunk`。
2. 若必须极简内容（`off`），请务必保留并同步 `manifest.json`。
