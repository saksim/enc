# 6_so_enc V2 Usage Manual

## 1. 这版工具解决什么问题

当前版本解决的是下面这条链：

```text
原始 .py
-> 加密后的 .py 中间文件
-> 递归 Cython 编译
-> Windows: .pyd / Linux: .so
```

和上一版不同，这一版的关键点是：

1. 中间产物是 `.py`，不是 `.pyx`
2. 可以只保护指定函数或类
3. 如果不指定，则默认保护当前脚本中所有顶层函数和类
4. 可以对整个目录下的所有 `.py` 递归处理
5. 编译阶段结合 `py2_linux_rec_opera.py` 进行批量构建

## 1.1 Python 版本兼容性

新版本要求已经对齐为：

```text
兼容 Python 3.6+
```

这意味着：

- `encryption_helper.py` 兼容 Python 3.6 语法
- `decryption_helper.py` 兼容 Python 3.6 语法
- `py2_linux_rec_opera.py` 兼容 Python 3.6 语法

注意：

- 当前兼容性是按代码实现对齐到 3.6
- 但如果你在 Python 3.6 环境运行，仍需确保对应版本的 `Cython`、`pycryptodome`、`setuptools` 可安装

## 2. 当前目录中的核心文件

- `encryption_helper.py`
  - 主入口
  - 负责扫描 `.py`
  - 负责 AST 选区
  - 负责把选中的函数/类替换成加密执行块
  - 负责生成中间 `.py`
  - 负责调用 `py2_linux_rec_opera.py` 递归批量编译

- `decryption_helper.py`
  - 提供 runtime 模板
  - 提供 AES-GCM 解密逻辑
  - 提供 XOR key 分片重组逻辑

- `py2_linux_rec_opera.py`
  - 批量递归编译器
  - 负责把输出目录中的所有 `.py` / `.pyx` 编译成 native extension
  - Windows 输出 `.pyd`
  - Linux 输出 `.so`

## 3. 这版的保护粒度

### 3.1 默认规则

如果你**不指定任何函数或类**，则：

- 当前文件中所有顶层 `def`
- 当前文件中所有顶层 `async def`
- 当前文件中所有顶层 `class`

都会被保护。

### 3.2 指定保护规则

你可以显式指定：

- 某些函数
- 某些类

未指定的函数/类保持明文。

### 3.3 什么叫“顶层”

这里只处理模块顶层定义，例如：

```python
def foo():
    pass

class Bar:
    pass
```

如果方法写在类里：

```python
class Bar:
    def method(self):
        pass
```

那么：

- 加密 `Bar`，就等于把类内部方法一起带走
- 不能直接单独点名某个 class method

## 4. 中间文件长什么样

当前中间文件仍然是 `.py`。

但被选中的函数/类源码，不再原样保留，而会变成：

1. 一个模块级的解密执行 helper
2. 多个加密 payload 调用点
3. 一个随机命名的 runtime 模块引用

也就是说，你看到的是类似：

```python
def __enc_exec_xxx(...):
    ...

__enc_exec_xxx((nonce, tag, body), key_parts)
```

而不是原始函数体本身。

## 5. 平台能力确认

### 5.1 Windows

当前已在本机实测通过：

```text
原始 .py
-> 加密后的 .py
-> py2_linux_rec_opera.py 批量编译
-> .pyd
```

### 5.2 Linux

当前代码链路已经实现：

```text
原始 .py
-> 加密后的 .py
-> py2_linux_rec_opera.py 批量编译
-> .so
```

但 Linux 现场编译在当前 Windows 机器上没有实机跑，所以 Linux 结果属于：

```text
[unverified]
```

也就是说：

- 代码支持已完成
- 真正上线前，必须在 Linux 机器上做一次 smoke test

## 6. 依赖要求

### 6.1 通用依赖

Windows / Linux 都要有：

```text
Python 3.6+
Cython
pycryptodome
setuptools
```

### 6.2 Windows 额外要求

Windows 还要有：

```text
Visual Studio C++ Build Tools
vcvars64.bat
```

当前你本机的 Python 是：

```text
D:\code_environment\anaconda_all_css\py311\python.exe
```

### 6.3 安装依赖

Windows：

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' -m pip install Cython pycryptodome setuptools
```

Linux：

```bash
python3 -m pip install Cython pycryptodome setuptools
```

如果 Linux 缺系统编译工具，还需要：

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev
```

## 7. CLI 参数说明

运行帮助：

```bash
python encryption_helper.py --help
```

当前参数如下。

### `--target` / `-t`

目标可以是：

- 单个 `.py`
- 一个目录

示例：

```bash
-t ./demo.py
```

```bash
-t ./my_project
```

### `--output-dir` / `-o`

输出加密后的中间 `.py` 目录。

示例：

```bash
-o ./encrypted_tree
```

### `--python-exe`

编译时使用哪个 Python。

Windows 支持：

```text
/d/code_environment/anaconda_all_css/py311/python.exe
```

### `--precheck-only`

只做项目语法预检，不进入加密、不进入编译。

适合在大项目上先做一次全量尸检。

### `--skip-bad-files`

如果某些 `.py` 本身语法非法：

- 默认行为：整轮中断
- 加上这个参数：跳过坏文件，继续处理其余文件

### `--compile`

加密中间目录生成后，立刻调用 `py2_linux_rec_opera.py` 进行递归编译。

### `--dist-dir`

把编译后的交付物复制到一个干净目录。

推荐总是使用它。

### `--function`

单文件模式下，指定只保护哪些顶层函数。

可重复写：

```bash
--function foo --function bar
```

### `--class`

单文件模式下，指定只保护哪些顶层类。

可重复写：

```bash
--class Foo --class Bar
```

### `--scope-config`

目录模式下使用的 JSON 配置文件。

用于指定：

- 哪个文件要保护哪些函数
- 哪个文件要保护哪些类

如果某个文件没在配置中出现，则默认该文件所有顶层函数/类全部保护。

## 8. `scope-config` 格式

示例：

```json
{
  "pkg/mod2.py": {
    "functions": ["use_it"],
    "all": false
  },
  "pkg/mod3.py": {
    "classes": ["SecretBox"],
    "all": false
  },
  "pkg/mod4.py": {
    "all": true
  }
}
```

解释：

- `pkg/mod2.py`
  - 只保护函数 `use_it`
- `pkg/mod3.py`
  - 只保护类 `SecretBox`
- `pkg/mod4.py`
  - 保护该文件中所有顶层函数和类

如果某个文件不在这个 JSON 中：

- 默认保护该文件所有顶层函数和类

## 9. 单文件案例

### 9.1 原始文件

`demo.py`

```python
def keep_plain(x):
    return x - 1

def secret_add(a, b):
    return a + b

class SecretBox:
    def __init__(self, value):
        self.value = value
```

### 9.2 只保护指定函数和类

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\encryption_helper.py `
  -t .\demo.py `
  -o .\demo_out `
  --function secret_add `
  --class SecretBox
```

执行结果：

- `keep_plain` 保持明文
- `secret_add` 变成加密执行块
- `SecretBox` 变成加密执行块
- 输出目录中会出现：
  - `demo.py`
  - 随机 runtime `.py`
  - `build_manifest.json`

### 9.3 不指定函数或类

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\encryption_helper.py `
  -t .\demo.py `
  -o .\demo_out
```

执行结果：

- `demo.py` 中所有顶层函数和类都被保护

## 10. 目录批处理案例

假设目录结构：

```text
my_project/
  pkg/
    __init__.py
    mod1.py
    mod2.py
  scope.json
```

其中：

`pkg/mod1.py`

```python
VALUE = 10

def add(a, b):
    return a + b + VALUE

class Box:
    def __init__(self, value):
        self.value = value

    def total(self):
        return self.value + VALUE
```

`pkg/mod2.py`

```python
from .mod1 import add

def use_it():
    return add(1, 2)
```

`scope.json`

```json
{
  "pkg/mod2.py": {
    "functions": ["use_it"],
    "all": false
  }
}
```

### 10.1 执行目录加密 + 编译

Windows：

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\encryption_helper.py `
  -t .\my_project `
  -o .\my_project_enc `
  --scope-config .\my_project\scope.json `
  --compile `
  --dist-dir .\my_project_release `
  --python-exe /d/code_environment/anaconda_all_css/py311/python.exe
```

Linux：

```bash
python3 ./encryption_helper.py \
  -t ./my_project \
  -o ./my_project_enc \
  --scope-config ./my_project/scope.json \
  --compile \
  --dist-dir ./my_project_release
```

### 10.2 结果说明

这条命令会做这些事：

1. 递归扫描目录下所有 `.py`
2. 为每个目录生成随机 runtime `.py`
3. 没写进配置的文件，默认全量保护顶层函数/类
4. `pkg/mod2.py` 因为配置里只点了 `use_it`，所以只保护它
5. 调用 `py2_linux_rec_opera.py` 对整个加密树递归编译
6. 把编译结果复制到 `my_project_release`

### 10.3 Windows 实测结果

这条目录批处理链在本机已实测通过，验证过：

```text
mod1.add(2, 3) -> 15
mod1.Box(5).total() -> 15
mod2.use_it() -> 13
```

## 11. release 目录里应该有什么

如果是目录模式，release 一般会保留：

```text
build_manifest.json
pkg/
  mod1.pyd 或 mod1.so
  mod2.pyd 或 mod2.so
  enc_rt_xxxxxxxx.pyd 或 enc_rt_xxxxxxxx.so
  __init__.py
```

说明：

- 主模块是编译后的扩展
- runtime 模块也是编译后的扩展
- `__init__.py` 会被一并复制，避免包导入失真

## 12. 导入验证方式

### Windows

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' -c "import sys; sys.path.insert(0, r'.\my_project_release'); from pkg import mod1, mod2; print(mod1.add(2,3)); print(mod1.Box(5).total()); print(mod2.use_it())"
```

### Linux

```bash
python3 -c "import sys; sys.path.insert(0, './my_project_release'); from pkg import mod1, mod2; print(mod1.add(2,3)); print(mod1.Box(5).total()); print(mod2.use_it())"
```

## 13. 常见规则

### 13.1 目录模式下 `--function` / `--class` 不能乱用

目录模式下：

- `--function`
- `--class`

会被直接拒绝。

因为目录模式应使用 `--scope-config`。

### 13.2 `output-dir` 不能放进目标目录里

例如下面这种是错误的：

```text
target = ./my_project
output-dir = ./my_project/out
```

原因：

- 生成结果会被下一轮扫描回去
- 容易形成自污染

正确做法：

```text
target = ./my_project
output-dir = ./my_project_enc
```

## 14. 常见报错与排查

### 14.1 缺少 `Cython`

现象：

```text
No module named Cython
```

处理：

```bash
python -m pip install Cython
```

### 14.2 缺少 `Crypto`

现象：

```text
No module named Crypto
```

处理：

```bash
python -m pip install pycryptodome
```

### 14.3 Windows 编译失败

优先检查：

1. Visual Studio C++ Build Tools 是否真的安装
2. `vcvars64.bat` 是否存在
3. Python 是否是正确位数
4. 是否是无权限环境

### 14.4 Linux 编译失败

优先检查：

1. `gcc` / `clang`
2. `python3-dev`
3. `Cython`
4. `setuptools`

### 14.5 清理 warning

你可能看到：

```text
warning: skip removing ...
```

这通常意味着：

- Windows 编译链仍占着 `.c`
- 或临时目录句柄还没释放

这不一定影响编译结果。

真正验收标准是：

1. `release` 目录有目标 `.pyd/.so`
2. 能成功导入并运行

### 14.6 项目预检失败

如果看到类似：

```text
precheck_total=133
precheck_valid=132
precheck_invalid=1
syntax_error=utils/report_helper.py:458:-1: ...
```

含义是：

- 工具在加密前先发现项目自身有语法坏文件
- 这不是加密器先把文件搞坏了

这时有两种处理方式：

1. 修原始坏文件后再跑
2. 加 `--skip-bad-files` 跳过它继续处理其他文件

## 15. 当前版本的边界

这版已经满足：

1. 中间文件是 `.py`
2. 可指定函数/类保护
3. 默认全量保护当前脚本所有顶层函数/类
4. 可递归处理目录下全部 `.py`
5. 可批量编译成 `.pyd` / `.so`

但有两点要如实说明：

### 15.1 只处理顶层函数/类

不会直接点名类内部方法。

### 15.2 Linux 编译现场未在本机实跑

Linux 路径代码已完成，但当前机器是 Windows，Linux 结果仍需在目标 Linux 环境验尸。

## 16. 推荐工作流

### 单文件

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\encryption_helper.py `
  -t .\demo.py `
  -o .\demo_out `
  --function secret_add `
  --class SecretBox `
  --compile `
  --dist-dir .\demo_release `
  --python-exe /d/code_environment/anaconda_all_css/py311/python.exe
```

### 目录

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\encryption_helper.py `
  -t .\my_project `
  -o .\my_project_enc `
  --scope-config .\my_project\scope.json `
  --compile `
  --dist-dir .\my_project_release `
  --python-exe /d/code_environment/anaconda_all_css/py311/python.exe
```

## 17. 最后两条经验

1. 目录模式永远优先用 `--scope-config`
2. 交付时永远看 `dist-dir` / release 目录，不看中间加密树

## 18. 已解决的问题总表

当前版本已经明确解决或缓解了这些问题：

1. 中间产物必须是 `.py`，而不是 `.pyx`
2. 可指定顶层 `function` / `class` 做选择性加密
3. 未指定时，默认保护该文件所有顶层函数和类
4. 同文件“前面定义、后面立刻调用”场景
5. 保留原符号名，不再因为“加密后名字变了”导致后续调用报错
6. 多行 `from ... import (...)` 不再被 helper / stub 插穿
7. 含大量单引号 / 双引号 / 三重引号的文件，不再因为按行切片而高概率留下残片
8. 生成后的加密 `.py` 会在写盘前先 `compile()`，提前发现坏产物
9. 项目级预检：可先扫描语法坏文件
10. 跳过坏文件：`--skip-bad-files`
11. 输出目录锁住时，可自动切换 fallback 目录继续跑
12. 批量编译器会跳过非法模块名文件，例如数字开头脚本
13. Python 3.6 语法兼容已落地
14. Python 3.11 项目级 `.pyd` 实测已通过

## 19. 项目级真实测试结果

### 19.1 Python 3.6

#### app_ess

```text
precheck_total=133
precheck_valid=132
precheck_invalid=1
```

唯一坏文件：

- `utils/report_helper.py`

#### app_platform

```text
precheck_total=216
precheck_valid=124
precheck_invalid=92
```

说明：

- `app_platform` 大量源码本身是 Python 3.7+/3.10+ 风格
- 不适合作为 Python 3.6 全项目编译目标

### 19.2 Python 3.11

#### app_ess

```text
precheck_total=133
precheck_valid=132
precheck_invalid=1
```

原始坏文件：

- `utils/report_helper.py`

加密阶段：

```text
processed_files=132
skipped_files=1
output_dir=source/enc311_app_ess
```

`.pyd` 编译阶段：

- 已实测通过

#### app_platform

```text
precheck_total=216
precheck_valid=213
precheck_invalid=3
```

原始坏文件：

- `app_runtime/auth.py`
- `app_runtime/task_status_oltp.py`
- `database/mysql/fdm/power_trade_dimension.py`

加密阶段：

```text
processed_files=213
skipped_files=3
output_dir=source/enc311_app_platform_v7
```

`.pyd` 编译阶段：

- 已实测通过

额外说明：

- `gunicorn.conf.py` 因模块名不合法会被编译器自动跳过

## 20. 真实项目中的坏文件类型

当前预检会发现两类典型坏文件：

### 20.1 原始语法错误

例如：

- `f-string expression part cannot include a backslash`
- `invalid non-printable character U+FEFF`

这类问题是源码本身的问题，不是加密器先搞坏的。

### 20.2 非法模块名

例如：

```text
src/20251226.py
test/20250901.py
test/20250917.py
gunicorn.conf.py
```

这类文件：

- Python 里可以作为脚本文件存在
- 但 Cython 模块编译时模块名不合法
- 当前批量编译器会自动跳过，并打印：

```text
invalid_module_name=...
```

## 21. 预检与跳过模式的推荐用法

### 21.1 先看尸单

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\encryption_helper.py `
  -t .\source\app_ess `
  --precheck-only `
  --python-exe /d/code_environment/anaconda_all_css/py311/python.exe
```

### 21.2 跳过坏文件继续生成中间 `.py`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\encryption_helper.py `
  -t .\source\app_ess `
  -o .\source\enc311_app_ess `
  --skip-bad-files `
  --python-exe /d/code_environment/anaconda_all_css/py311/python.exe
```

### 21.3 再批量编译 `.pyd`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\py2_linux_rec_opera.py .\source\enc311_app_ess
```

## 22. 当前最终结论

如果魔尊问得最直接：

### “正常合法的 Python 代码，现在能不能转成加密后的 `.py` 再变成 `.pyd`？”

答案是：

```text
可以，且已经在真实项目 app_ess / app_platform 上用 Python 3.11 实测通过。
```

### “为什么还有个别文件不过？”

因为那些文件属于：

1. 原始源码本身语法非法
2. 或者文件名不适合做 Cython 模块名

这类问题不属于加密器主链问题。
