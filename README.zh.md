# DecBench ida-agent 迁移版（中文说明）

本目录是在上游 [DecBench](https://github.com/Noelo-Lab/decbench) 原版基础上，
只迁移了一个实验后端的精简环境，用于 **LLM Coding Agent 的反编译实验**
（Agent 后训练 / 蒸馏等），并包含匿名输入验证与本地固定样本评测辅助脚本。

## 目录里有什么

| 路径 | 说明 |
| --- | --- |
| `decbench/` | 上游 DecBench 完整管线（compile → decompile → evaluate） |
| `decbench/decompilers/agent_ida.py` | ida-agent 后端 |
| `scripts/prepare_ida_agent_eval.py` | 本地样本冻结、输入校验和正式驱动入口 |
| `scripts/serve_qwen_pilot.py` | Qwen3.5 四卡服务、思考模式及部署记录 |
| `scripts/compare_ida_agent_pilot.py` | 固定分母的逐函数比较与运行审计 |
| `.tools/ida-pro-9.3/` | IDA Pro 9.3 安装树 + license（免安装） |
| `.tools/host-gcc-12.3.0/` | x86-64 本地 GCC（编译基准语料，不依赖系统 gcc） |
| `.tools/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/` | ARM 交叉工具链（CPS/embedded 语料） |
| `.tools/jdk-17.0.20.1+1-jre/` | JDK17（GED 指标的 Joern 需要） |
| `tests/example_project/` | 一个几函数的小 C 工程，用来快速跑通流程 |

`.tools/` 整体被 gitignore（含 license、本地推理环境和缓存），**不要提交**。

`ida-agent` 的工作方式：对每个目标函数，启动一个 Claude Agent SDK 的
agent，给它一个 stripped binary 和一套 IDA MCP 分析工具（元数据 /
反汇编 / Hex-Rays 伪码 / 交叉引用 / 原始字节），让 agent 自主探索后写出该函数的 C
代码；产出再走标准指标（GED / type_match / byte_match）打分。agent 没有
shell，文件写入被限制在交付文件上；交付前有一道 `gcc -fsyntax-only`
编译门，失败会把错误回传给 agent 修订（默认最多 2 轮）。
当前工具版本为 1.1.0，已移除 `list_functions`，支持 IDA 名称和分页；
可选 `force` 会在临时 IDA 数据库的已识别代码处创建函数。
Qwen3.5-4B 的 verl 训练接入见 [训练说明](docs/verl-training.zh.md)。

## 环境要求

- Linux x86-64，Python ≥ 3.10，gcc，make
- Node.js + `claude` CLI（agent 循环由它承载）：
  `npm install -g @anthropic-ai/claude-code`

## 安装

```bash
cd decbench-agentic-rl
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[agent]"                # decbench + claude-agent-sdk
pip install .tools/ida-pro-9.3/idalib/python/idapro-0.0.7-py3-none-any.whl   # 无头 IDA
```

## 环境变量

每次使用前（可写进 activate 脚本）：

```bash
export IDADIR="$PWD/.tools/ida-pro-9.3"
export HEXRAYS_LICENSE_FILE="$IDADIR/idapro.hexlic"
# GED 指标走 Joern，需要 JDK17（已含在 .tools/）
export JAVA_HOME="$PWD/.tools/jdk-17.0.20.1+1-jre"
```

IDA 的路径解析以 `IDADIR` 为准。换机器后需确认虚拟环境入口路径有效，
并由当前用户完成 IDA 首次许可确认及 IDAPython 配置。若想固化路径，也可以在装完
idalib wheel 后运行
`python .tools/ida-pro-9.3/idalib/python/py-activate-idalib.py -d "$IDADIR"`
（它把绝对路径写进配置，换机器后需重跑）。

## 接模型

agent 走 Anthropic Messages API 兼容协议。设置两个环境变量即可接
任意端点（官方 API、vLLM/网关的自部署模型均可）：

```bash
export ANTHROPIC_BASE_URL="http://<你的推理服务>:<端口>"
export ANTHROPIC_AUTH_TOKEN="<API key>"
```

**模型名即版本号**：用 `-d ida-agent@<model>` 指定，例如本机网关上
部署的 `qwen3.5-9b` 就写 `-d ida-agent@qwen3.5-9b`；结果列、checkpoint
里记录的都是这个名字。要求模型支持工具调用（tool use）。

## 准备固定样本评测

普通 `decbench run` 不会自动为 Agent 剥离调试信息，也不读取
`DECBENCH_SAMPLESET_MANIFEST`；不能用于匿名反编译对比。后端现在会拒绝
未剥离的 ELF、真实函数名以及超过上限的目标集合。

已有 `results/{O0,O2}/{bzip2,chibios}/compiled/` 时，可以冻结本地样本：

```bash
.venv/bin/python scripts/prepare_ida_agent_eval.py prepare \
    results results/deepseek-v41-flash-pilot
.venv/bin/python scripts/prepare_ida_agent_eval.py check \
    results/deepseek-v41-flash-pilot --resources
```

目标目录必须不存在；已准备过则只运行 `check`。准备过程不调用模型。
原生 IDA 基线、DeepSeek 官方 API 启动命令、预算和覆盖率检查见
[固定样本评测说明](docs/ida-agent-evaluation.zh.md)。模型调用过程保存在
`<结果树>/<优化等级>/<项目>/decompiled/traces/`。

本地 Qwen3.5-0.8B 非思考、Qwen3.5-4B Thinking 四卡部署及
`--reference-tree` 复用旧样本的命令见上述说明。
所有模型必须使用同一清单和运行预算；本地非思考模式与 DeepSeek 的思考设置差异
应在对比报告中注明。

## sample set：评估 agent 反编译效果的基准

这套环境的核心用途：**在一份基准语料（sample set）上评估 agent 的
反编译效果**。语料取自 `projects/` 下的真实开源项目（`sailr/` 为
x86-64 桌面程序，`cps/` 为 ARM 嵌入式固件），用本地工具链编译出带
DWARF 调试信息的基准 binary——随产物保存的预处理 `.i` 文件就是各函数
的 ground-truth 源码。评估闭环是：

1. **编译**：若干项目 × 优化等级（O0 / O2 / O2-noinline），得到基准
   binary（编译产物在 `results/<O?>/<project>/compiled/`）；
2. **反编译**：`ida-agent` 只拿 stripped 拷贝，对每个目标函数重建 C；
3. **打分**：把 agent 产出与 ground truth 对照——GED（控制流结构
   距离）、type_match（类型恢复）、byte_match（重编译后操作数一致率）
   等指标衡量反编译质量，scoreboard 自动汇总。

架构 × 优化等级的组合天然构成难度阶梯：O0 最接近源码、O2 内联后单
函数膨胀最难，ARM（Cortex-M/Thumb）考察跨架构能力。每个函数的完整
agent 过程（prompt、工具调用、输出）与评分一一对应地落在
`results/<O?>/<project>/decompiled/traces/`，做 prompt / reward 设计时
用同一份语料即可复现对比。

## 编译基准语料（projects/）

上游语料分 `sailr/`（x86-64 桌面程序）和 `cps/`（ARM 嵌入式，自带
arm-none-eabi 交叉构建）。两套编译器都已放在 `.tools/` 下，把三个目录
注入 PATH 即可（连同 strip 垫片）：

```bash
export PATH="$PWD/.tools/bin:$PWD/.tools/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/bin:$PWD/.tools/host-gcc-12.3.0/usr/bin:$PATH"
```

只编译两个项目的示例（随后通过上述固定样本流程调用 Agent）：

```bash
.venv/bin/python -m decbench.cli run projects/sailr/bzip2.toml projects/cps/chibios.toml \
    -O O0 -O O2 --skip-decompile --skip-evaluate -j 1 -o results/compiled-local
```

产物在 `results/compiled-local/<O?>/<project>/compiled/`；将准备命令的
源目录换成 `results/compiled-local`。规模化编译使用 `scripts/compile_all.py`，
参见 `docs/benchmarking.md`。单项目只编译示例：

```bash
.venv/bin/python -m decbench.cli run projects/sailr/bzip2.toml \
    -O O0 -O O2 --skip-decompile --skip-evaluate -o results/compiled-local
```

源码首次会从 TOML 里的 `source_remote` 下载；如本机代理干扰直连，
先 `unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy`。

## 常用旋钮（环境变量，均有合理默认）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `DECBENCH_IDA_AGENT_MAX_TURNS` | 40 | 每函数 agent 最大轮数 |
| `DECBENCH_IDA_AGENT_COMPILE_CHECK` | 1 | 编译门开关 |
| `DECBENCH_IDA_AGENT_COMPILE_RETRIES` | 2 | 编译失败回传修订次数 |
| `DECBENCH_IDA_AGENT_PATH_GUARD` | 1 | 限制 agent 只能写交付文件 |
| `DECBENCH_LLM_SAVE_TRACES` | 1 | 保存 agent 过程 trace |

## 提醒

- `.tools/`（约 3.3 GB，含 IDA license 与双架构工具链）已被 gitignore，
  不要以任何方式提交。
- 上游仓库的完整文档在 `docs/`（英文），本文件只覆盖跑通 ida-agent
  所需的最小路径。
