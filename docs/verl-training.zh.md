# IDA 反编译任务接入 verl

本地适配器使用 verl 的多轮 AgentLoop 训练 Qwen3.5-4B。策略由 verl/vLLM
生成，IDA 与评分在独立的 DecBench Python 子进程中执行。Claude Agent SDK
不参与训练。IDA 后端与训练工具接口同步更新；指标算法和历史实验保留。

## 接口与奖励

实现位于 `decbench/rl/`：

- `tasks.py`：私有任务清单、匿名 prompt、九种工具 schema。
- `worker.py`：每条轨迹独立 IDA 会话、Read/Write/Edit、编译反馈和终局评分。
- `bridge.py`：异步子进程协议与超时清理。
- `verl_agent.py`：复用 verl 的 Qwen 工具解析、逐轮生成和 response mask。

一个 episode 对应一个 stripped ELF 中的目标地址。工具名称沿用 IDA Agent 的
六个分析 MCP 名称与 Read/Write/Edit，但不通过 MCP 网络服务调用。
当前版本为 `ida-mcp-1.1.0`：`get_metadata`、`decompile_function`、
`disassemble_function`、`get_xrefs_to`、`get_xrefs_from`、`read_bytes`。
已移除 `list_functions`；地址支持十六进制和 IDA 名称。反汇编支持
`offset`/`length`（每页最多 4000 条），交叉引用支持 `offset`（每页 200 条），
`read_bytes` 的 `size` 默认 64，范围 1–512。
反编译和反汇编的可选 `force=true` 仅可在已识别代码处创建函数，改变当前
episode 的临时 IDA 数据库。因此不能将所有调用描述为严格只读。
文件工具仅接受 `decompiled.c` 或 `./decompiled.c`；不支持读取其他文件。
Write/Edit 保存后自动返回目标架构编译器的语法检查结果。最终答案必须写文件，
最后一条 assistant 文本不作为 C 输出。当前接口每次只执行一个工具调用。

工具观察的 `response_mask=0`，模型生成的 token 为 1。每条轨迹记录完整 token IDs、
生成 logprobs、工具请求/结果、最终代码和评分。`episodes/<uuid>/trajectory.json`
用于审计；`failure.json` 记录导致整轮中断的基础设施错误。

终局奖励是 **byte_match v8 代理奖励**，不是语义等价成功率：

- 无输出、无法形成目标函数、评分流程不可编译：0。
- 可以评分：使用 byte_match 的 `[0,1]` 分数，包括其既有确定性修补。
- 工具参数或路径错误：反馈给模型，允许继续修订。
- IDA 启动、评分依赖、worker 通信或沙箱故障：抛错中止，不伪装成低分样本。
- 不使用 Union，也不将 GED 满分或类型匹配满分当作行为正确。

编译使用 bubblewrap：无网络，只挂载系统运行库、所需编译工具链和当前 episode
临时目录。源项目、私有原始二进制和凭据目录不挂载给编译器。IDA 只分析，不执行
目标二进制；该适配器拒绝 malware 任务。第一版没有隐藏行为测试、语义等价验证，
也没有针对 asm 等表达方式的额外奖励防作弊规则，不应直接用于宣称语义能力提升。

## 环境

适配的 verl 源码版本为
`7aed6b230776f963fa09509c10d9c3a767d1102c`（本机 `v0.8.0` 源码目录的 HEAD）。
`.tools/verl-src` 从该提交导出，不包含原目录未提交的自定义 loss 修改，仅应用下面
记录的 SDPA padding 和 FSDP2 checkpoint 兼容补丁。
训练环境是 `.tools/verl-env`，与 `.tools/qwen-vllm` 的历史推理环境分开。
训练组合固定为 vLLM 0.18.0 / PyTorch 2.10.0 / Transformers 5.3.0。
历史推理的 vLLM 0.31 已移除该 verl 版本引用的 `FusedMoE` 符号，不能直接混用。

直接依赖在 `configs/verl/requirements.txt`，两个明确的兼容性覆盖在
`configs/verl/compat-overrides.txt`：Qwen3.5 需要 Transformers 5，而旧 vLLM
wheel 元数据仍声明 `<5`；新版 OpenCV 需要 NumPy 2，而 verl 元数据仍声明 `<2`。
因此普通依赖检查可能报告这两项冲突，必须结合实际运行验证，不能仅凭安装成功
宣称支持。迁移机器或升级任一组件后，重新运行下文检查与单步训练。

从 GitHub 克隆后，在项目根目录执行。虚拟环境、工具安装、模型权重和结果不随仓库发布。
先按 [安装说明](../README.zh.md#安装) 创建 `.venv`，安装 DecBench 和本地合法授权的 IDA；
训练链路还需要宿主的 gcc、strip、bubblewrap，以及对应任务架构的编译器。
使用 Python 3.10，并为训练建立独立环境：

```bash
git clone https://github.com/verl-project/verl.git .tools/verl-src
git -C .tools/verl-src checkout 7aed6b230776f963fa09509c10d9c3a767d1102c
```

已有该目录时先检查版本，无需重复克隆。然后安装固定依赖和兼容补丁：

```bash
UV_CACHE_DIR="$PWD/.tools/uv-cache" uv venv --python 3.10 .tools/verl-env
UV_CACHE_DIR="$PWD/.tools/uv-cache" uv pip install \
  --python .tools/verl-env/bin/python \
  --overrides configs/verl/compat-overrides.txt -r configs/verl/requirements.txt
UV_CACHE_DIR="$PWD/.tools/uv-cache" uv pip install \
  --python .tools/verl-env/bin/python --no-deps -e .tools/verl-src
patch -p1 --forward -d .tools/verl-src < configs/verl/sdpa-padding.patch
patch -p1 --forward -d .tools/verl-src < configs/verl/fsdp2-cpu-checkpoint.patch
```

该补丁使缺少 `flash_attn` 时的 padding 操作使用 verl 自带的纯 PyTorch 实现
（文件名为 `npu_flash_attn_utils.py`，这几个函数不依赖 NPU）。attention 仍使用
SDPA，不模拟 FlashAttention CUDA 内核。已验证混合左右 padding 的还原及梯度。
第二个补丁在 FSDP2 `CPUOffloadPolicy` 生效时禁止 checkpoint 保存逻辑再次
手动搬移模型，避免 CPU/CUDA storage 冲突。两份补丁都只应用一次；启动记录
同时保存补丁和实际 verl 源文件的哈希。

DecBench worker 使用 `.venv/bin/python`，本机 IDA 位于 `.tools/ida-pro-9.3`。
训练 launcher 为 worker 指定编译工具链和 IDA 路径，只传递最少环境变量。
需要本机 IDA 已完成许可配置、`bwrap` 可用且内核允许非特权 namespace。
工具 worker 当前在每个 AgentLoopWorker 内串行，默认只开一个 AgentLoopWorker。

训练启动记录 `launch.json` 包含实际包版本、GPU UUID、数据锁哈希和启动参数。
不要直接将历史推理服务的四卡配置视为训练配置：FSDP 优化器、激活和 rollout
引擎共用显存，训练配置须经过实际参数更新验证。

## 准备数据

所有准备命令都要求新输出目录，已有锁文件不改写。准备后若适配器代码变化，
重新准备一个新目录。清单记录 `environment_version`，并冻结 `tools.json`；
缺少版本或使用旧工具版本的数据会被拒绝。保留原来的 24 函数 benchmark：
默认从 `configs/verl/heldout-projects.json` 读取
保留评测项目（bzip2、chibios），禁止它们进入训练集。需要匹配其他评测集时，
使用 `--heldout-manifest` 显式指定其 manifest；克隆后不依赖历史 results 目录。

先生成与 benchmark 无关的合成任务，仅用于链路检查：

```bash
.venv/bin/python scripts/prepare_verl_tasks.py \
  --smoke --output results/verl-smoke-data
```

导出包括 8 个训练任务和 2 个验证任务，标记 `smoke_only=true`。这不是有效的模型
泛化评测集，不能据此报告训练提升。

接入实际语料时提供 JSON manifest，所有 binary 必须是已编译的非恶意 ELF，
带完整函数符号和用于 byte_match 的编译信息。相对路径以 manifest 所在目录为基准：

```json
{
  "tasks": [
    {
      "project": "training-project",
      "split": "train",
      "is_malware": false,
      "original_binary": "compiled/program",
      "function": "function_name",
      "address": 4198400
    },
    {
      "project": "validation-project",
      "split": "validation",
      "is_malware": false,
      "original_binary": "compiled/other_program",
      "function": "other_function",
      "address": 4198432
    }
  ]
}
```

```bash
.venv/bin/python scripts/prepare_verl_tasks.py \
  --manifest data/tasks.json --output results/verl-real-data
```

同一项目的不同函数、版本及 O0/O2 必须放在同一 split；相同 binary 哈希也不得
跨 split。这里的项目标识应反映实际源码血缘，不能用不同名字绕过分组。
准备器验证 strip、复制并哈希二进制、检查重复目标，生成 parquet 和私有清单。
prompt 中只包含匿名地址，不包含源函数名、原始二进制路径或参考 C。
当前可用的 bzip2/ChibiOS 已属于保留评测项目，正式训练应另备项目。

## 验证与训练

脚本驱动真实 verl/Qwen 解析器和真实 IDA，但不加载策略权重：

```bash
.tools/verl-env/bin/python scripts/check_verl_decompiler.py \
  --dataset results/verl-smoke-data --output results/verl-scripted-check
```

`check.json` 标记 `scripted_verl_integration_not_model_training`。
该检查验证工具交互、奖励和 mask，不能代替真实生成或训练测试。

检查完整 Hydra 配置：

```bash
.tools/verl-env/bin/python scripts/train_verl_decompiler.py \
  --dataset results/verl-smoke-data --run-dir results/verl-train-check \
  --config-only
```

首轮配置位于 `configs/verl/decbench_grpo.yaml`：Qwen3.5-4B、非思考、GRPO、
每 prompt 两个 rollout、四卡 FSDP2、推理 TP=2、12 个 assistant 轮次、
2048 prompt / 2048 response token、默认只更新一步并保存 checkpoint。
response 预算包含工具观察 token；这些观察 token 占上下文，但通过 mask 排除在
策略损失之外。
这与旧 benchmark 的 Thinking 模式和预算不同，应作为新实验记录。

选择四张空闲卡运行，下面的编号只是示例：

```bash
.tools/verl-env/bin/python scripts/train_verl_decompiler.py \
  --dataset results/verl-smoke-data --run-dir results/verl-train-smoke \
  --gpus 1,2,3,4
```

launcher 检查显存占用和利用率，遇到占用则拒绝启动，不停止已有作业。
`run-dir` 必须不存在；日志、checkpoint 和 episodes 全部进入该目录。
Ray socket 使用 `/tmp` 下的短路径，避免 Unix socket 路径长度限制。
检查 `exit.json`、训练日志、实际 checkpoint 和梯度/奖励记录后，才能确认参数更新。

正式实验使用独立数据及目录，并通过 Hydra overrides 设置训练步数和批次：

```bash
.tools/verl-env/bin/python scripts/train_verl_decompiler.py \
  --dataset results/verl-real-data --run-dir results/verl-real-run \
  --gpus 1,2,3,4 trainer.total_training_steps=100 trainer.total_epochs=20
```

训练步数不能超过数据批次 × epoch 能提供的更新数。后续扩大规模前，实测
episode 耗时、有效输出比例、组内奖励方差、环境失败率和峰值显存。
GRPO 组内分数全部相同可能没有有效策略梯度；进程退出 0 本身不是训练成功证明。

训练结果保持本地。发布 benchmark 分数仍需原有 overlays/finalize/audit 流程；
贡献和公开发布遵循仓库的人工审阅要求。

## 升级前的本机训练记录（2026-10-19）

以下训练使用升级前的工具环境，不能作为新版环境的训练验证。
合成任务目录为 `results/verl-qwen35-4b-smoke-v5`，真实训练结果为
`results/verl-qwen35-4b-train-smoke-v6`。该运行使用上面的默认配置和两份兼容补丁，
在 GPU 1、2、3、4 上完成一次 GRPO 更新，退出码为 0。

- 2 个 prompt × 2 条轨迹；组内奖励分别为 `[0.555556, 0.625]` 和
  `[0, 0.523810]`。3/4 轨迹写出可评分代码，1/4 未输出，环境基础设施失败为 0。
- `actor/grad_norm=5.131615`，学习率 `1e-6`；更新调用约 36.46 秒，
  整个训练 step 约 258.72 秒，不含模型和推理引擎初始化。
- `checkpoints/global_step_1/actor` 包含四份模型、四份优化器和四份额外状态分片，
  总计约 51 GiB。已读回全部分片，并确认各 rank 的优化器步数为 1。
- rank 0 第一层 input layernorm 的 640 个 FP32 参数均相对原始模型变化，
  最大绝对变化约 `1.0133e-6`。这是实际参数更新证据，不是能力提升证据。
- `verification.json` 保存逐条轨迹摘要、完整指标、分片检查及参数抽检；
  `source/` 保存本次适配器、启动器、配置和补丁快照。训练后四张 GPU 已释放。

最终脚本集成检查在 `results/verl-integration-check-v3/check.json`，验证真实 IDA、
编译评分、Qwen 工具解析和 token mask，但使用脚本回复，不代表模型训练。
适配器单元测试为 13 项通过。微型模型 FSDP2 CPU 卸载保存/读回验证位于
`results/verl-fsdp-checkpoint-check-v1/check.json`。

退出清理阶段出现 DataLoader 子进程被杀死的日志；该日志出现在训练完成后，
本次 step、checkpoint、优化器状态和参数变化均已独立核验。当前只验证了单步，
尚未验证长训或 checkpoint 恢复后的继续训练。verl 的 MFU 估算器也不支持
`qwen3_5`，其输出 0 不能解释为实际 GPU 利用率为 0。

## 新版反编译环境验证（2026-10-19）

从用户提供的只读上游副本同步 IDA 后端，未写入源目录；
源位置与文件哈希保存在下述本地升级审计中。
该副本未包含 Git 提交信息，使用逐文件 SHA-256 记录来源；升级审计目录为
`results/verl-environment-upgrade-20261019-192705`，包含升级前备份、上游副本、
本地差异补丁、哈希与检查结果。本地保留匿名目标校验、固定样本防截断、
Qwen thinking/title 控制、隔离编译和现有评分修复。

- 回归测试：60 项通过、6 项跳过；新增检查覆盖工具 schema 一致性、可选参数、
  移除工具的拒绝、旧环境清单拒绝、force 的已识别代码限制和字节读取边界。
- 最终冻结数据：`results/verl-qwen35-4b-smoke-v7`，8 个训练和 2 个验证合成任务。
  `v6` 是源码说明修正前的中间快照，保留但不用于当前启动。
- 真实 IDA + verl 集成：`results/verl-integration-check-v5/check.json`；
  九种工具全部成功，代理奖励 1.0，prompt 1639 token、生成 389 token、
  工具观察 503 token，mask/logprob 对齐通过。该检查使用脚本回复。
- 新数据的完整 Hydra 配置和代码锁检查通过。新版环境尚未重新验证梯度更新：
  检查时仅 GPU 4、6 空闲，既定配置需要四张空闲卡，未启动训练。

四张卡空闲后选择其实际编号运行（不要原样使用占位符）：

```bash
.tools/verl-env/bin/python scripts/train_verl_decompiler.py \
  --dataset results/verl-qwen35-4b-smoke-v9 \
  --run-dir results/verl-qwen35-4b-train-smoke-v7 \
  --gpus <四张空闲卡的编号，以逗号分隔>
```


## 相对路径与目录迁移

代码通过脚本位置识别项目根目录，不要求特定用户名或克隆位置。
命令行的 `--dataset`、`--output`、`--run-dir`、`--model` 相对路径以调用时的
工作目录为基准；manifest 中的 binary 路径相对 manifest 所在目录。
模型默认放在项目内的 `models/Qwen/Qwen3.5-4B`，可用 `--model` 或
`DECBENCH_RL_MODEL` 指向外部模型；无需修改受版本控制的配置，例如：

```bash
.tools/verl-env/bin/python scripts/train_verl_decompiler.py \
  --dataset results/verl-qwen35-4b-smoke-v9 \
  --run-dir results/verl-config-check --config-only \
  --model ../models/Qwen/Qwen3.5-4B
```

准备器生成的 `agent.yaml` 使用环境变量插值，launcher 自动设置
`DECBENCH_RL_REPO`、`DECBENCH_RL_DATASET` 和 `DECBENCH_RL_RUN`；绝对路径
仅在运行时解析，不写死在可移植配置中。binary 路径相对数据目录保存。
项目和新冻结数据一起搬迁，或单独移动数据目录后，都无需改写锁文件。
历史配置 v8 及以前仍包含固定路径，保留作为历史记录；当前快照为
`results/verl-qwen35-4b-smoke-v9`。

Python venv 的 console-script shebang 和 editable 安装由安装工具生成，通常包含
绝对路径，不能当作可搬迁的依赖包。克隆到新位置后按安装步骤重建 `.venv` 和
`.tools/verl-env`，不要提交或复制已安装的虚拟环境。模型及合法授权的 IDA 安装
另外准备；不应把旧目录软链接作为运行前提。

`.gitignore` 排除了 `.venv`、`.tools`、`models`、`results*`、`trace` 和 IDA license。
历史实验审计中的绝对路径保留用于来源追溯；它们不属于启动配置。

可移植性验证记录：`results/verl-portability-check-v1/verification.json`。
代码和 v9 数据复制到另一个目录后，从无关工作目录启动，原锁文件未修改，
Hydra 配置与真实 IDA 九工具链路均通过；回归测试 60 项通过、6 项跳过。
此次复用本机已有工具及虚拟环境，不等于验证全新机器安装或 GPU 训练。
