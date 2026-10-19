# IDA Agent 本地固定样本评测

需要使用 verl 训练工具调用策略时，见 [verl 训练接入](verl-training.zh.md)。

2026-10-19 已按只读源副本同步 IDA MCP 1.1.0：移除 `list_functions`、增加
`read_bytes`，支持 IDA 名称、反汇编/交叉引用分页以及临时 IDB 的 `force` 创建函数。
编译修订轮次延续同一 SDK 会话，并保存逐轮 C；保留本地匿名输入与 Qwen 开关。
SDK 默认模型沿用新版的 `glm-5.3-flash`，verl 配置仍显式使用 Qwen3.5-4B。
工具和提示词已变化，旧评测锁及教师轨迹不能直接当作当前工具环境的证据。
训练使用独立 AgentLoop 和结果目录，本文的固定评测样本继续作为保留集。

此流程评测模型使用 IDA/Hex-Rays 工具恢复 C 的能力。准备脚本支持
本机的 DeepSeek 官方接口、本地 Anthropic 兼容服务和 bzip2、ChibiOS ELF 产物；不等同于网站发布的
250 函数 sample-set，也不能将结果外推为完整语料的成绩。

## 准备与启动

在仓库根目录运行，使用实际存在的 `.venv/bin/python`。迁移过来的
`.venv/bin/decbench` 可能仍指向旧机器的解释器。

已有 `results/{O0,O2}/{bzip2,chibios}/compiled/` 时：

```bash
.venv/bin/python scripts/prepare_ida_agent_eval.py prepare \
    results results/deepseek-v41-flash-pilot

.venv/bin/python scripts/prepare_ida_agent_eval.py check \
    results/deepseek-v41-flash-pilot --resources
```

`prepare` 不调用模型，也不重新编译。它复制原始 binary 和 `.i` 文件、
制作经过验证的 stripped 副本、冻结函数清单及配置。目标目录必须不存在，
失败的准备不会留下半成品目录。需要重新抽样时使用新目录。

先运行原生 IDA 基线，验证目标解析和评分（不调用模型 API）：

```bash
.venv/bin/python scripts/prepare_ida_agent_eval.py run \
    results/deepseek-v41-flash-pilot --backend ida
```

以下命令会调用付费 DeepSeek API；Key 文件应仅包含密钥：

```bash
.venv/bin/python scripts/prepare_ida_agent_eval.py run \
    results/deepseek-v41-flash-pilot \
    --backend ida-agent@deepseek-flash --key-file ~/.key/deepseek
```

`deepseek-flash` 在 2026-10-10 的官方模型说明中对应 DeepSeek-V4.1-Flash。
这是服务端别名，不保证以后仍指向同一模型版本；比较时保存日期、响应模型字段
和 [官方版本说明](https://api-docs.deepseek.com/quick_start/pricing)。

运行包装器只从 Key 文件读取认证值，不把它写入实验配置或锁文件。
准备脚本固定 `https://api.deepseek.com/anthropic`，并将模型请求交给本机
Claude Agent SDK；IDA 工具结果会传输到该官方服务。

## 固定样本与预算

默认每个 binary 抽取 4 个函数，当前两项目 × O0/O2 共 6 个 binary，合计
24 个函数。筛选规则与模型结果无关：名称能唯一映射到 DWARF 源函数、
有 `.i` 所属单元、有类型 ground truth、机器码大小在 32–4096 字节。
按大小排序后切成 4 个等数量桶，各用 seed 1337 选一个函数。
这是限制范围的小样本，排除了过小、超大和缺少类型真值的函数。

`experiment.lock.json` 保存目标地址、大小、源单元、候选数量、输入文件、
代码、项目配置、IDA 核心库/反编译插件及编译工具哈希和 Python/SDK/CLI 等版本。
续跑前发生变化会拒绝启动。锁文件不包含许可证或密钥内容。
它固定的是已有编译产物，不声称能重现其首次构建过程。

`decompilers.toml` 固定模型后端参数，优先于用户目录中的配置：

| 参数 | 本轮值 |
| --- | --- |
| API 模型 | `deepseek-flash` |
| effort | `high` |
| thinking 开关 | SDK/服务默认；首次模型预评测须核对实际请求行为 |
| Agent 最大轮数 | 每次调用 40 |
| Agent 超时 | 每次调用 300 秒 |
| 编译修订 | 最多 1 次额外 Agent 调用 |
| 目标上限 | 每 binary 4 个，超出报错 |
| 并发 | 1 个 binary |
| binary 总超时 | 3600 秒，含原生分析与 Agent 子进程 |
| 内存上限 | 每 binary 16 GiB，swap 禁用 |
| GED 节点上限 | 200 |
| DWARF abstract-origin 扩展 | 关闭 |

轮数、时间上限不是金额上限。SDK 的 `cost_usd` 可能按其他厂商价格估算，
不能直接当作 DeepSeek 实际账单；费用应结合官方账单或当期价格和 token 统计。

## 匿名输入契约

`run` 使用 `scripts/run_benchmark.py`，由父进程保存真值、过滤目标并将地址
传给反编译子进程。strip 必须成功，并验证所有可执行代码段保持不变；
ELF 不得残留静态符号表、DWARF、压缩 DWARF 或外部 debug-link。
旧的 stripped 缓存同样需要验证，不能仅相信修改时间。

`ida-agent` 在打开 IDA 前再次检查 ELF 和匿名 `sub_<address>` 标签，并拒绝
静默截断目标。共享 IDA 会话打开的文件统一叫 `target.bin`，工具元数据不再
携带原始文件名。动态导入符号、字符串常量及二进制内原有内容仍保留，这是
正常静态分析可见的信息；不能据此声称完全无法识别项目。

普通 `decbench run ... -d ida-agent@...` 不执行这套地址门控与 stripping，
现在会被后端拒绝。此前单函数 `next_job` 试跑只证明接口连通，其未匿名输入
的分数不能纳入正式对比。

## 覆盖率、恢复与报告

运行后自动生成 `coverage-<backend>.json`，按清单固定分母分别记录未出现的行、
失败或未尝试的函数，以及各指标缺失值。缺失不等于 0，不应只报告成功子集均值。
Type 对 Agent 使用文档所述的 fallback，不能宣称与原生地址证据等价。

```bash
.venv/bin/python scripts/prepare_ida_agent_eval.py audit \
    results/deepseek-v41-flash-pilot --backend ida-agent@deepseek-flash
```

相同 `run` 命令会通过驱动的项目/后端 checkpoint 续跑。已有后端结果中的失败
通常也会视为已记录，不会自动重新购买调用；进程在项目 checkpoint 写入前中断
也可能重做该项目的调用。因此不能把它当作逐函数 exactly-once 续跑。
重试策略必须事先决定，并用独立实验记录保留首次失败，不能挑最好结果。

局部评测汇总仍需人工检查 `run-*.log`、逐函数结果和 trace；驱动退出 0 不代表
所有函数和指标都成功。网站发布还须走 [benchmarking.md](benchmarking.md)
规定的 overlays → finalize → audit 流程；本准备脚本不发布网站、数据集或提交 PR。

## 本轮离线评分修正

2026-10-10 的 24 函数运行完成后，审计发现 ChibiOS 的首个 DWARF 单元为
汇编启动代码，旧版 `producer_flags` 提前返回空参数，导致 ARM 重编译没有沿用
Thumb、CPU 和优化参数。修复后 byte_match 缓存版本升为 8，对 IDA 和模型结果
一起离线重算；不重新调用模型。首轮文件保存在实验目录的 `first-pass-inline/`。

模型运行的 `experiment.lock.json` 保留原值，离线修正另记在
`metric-refresh-provenance.json`。因此，原目录再执行 `check` 或 `run` 会因
这两处代码更新而拒绝继续，这是预期的漂移保护；不要改写旧锁绕过它。
后续新模型实验应使用新的输出目录执行 `prepare`。

## Qwen3.5-0.8B 四卡本地评测

推理环境独立于评测 `.venv`。安装固定版本后，在仓库根目录启动服务：

```bash
UV_CACHE_DIR="$PWD/.tools/uv-cache" uv venv --python /usr/bin/python .tools/qwen-vllm
UV_CACHE_DIR="$PWD/.tools/uv-cache" uv pip install \
    --python .tools/qwen-vllm/bin/python vllm==0.31.0
.venv/bin/python scripts/serve_qwen_pilot.py
```

服务读取 `/home/lxy/models/Qwen/Qwen3.5-0.8B`，使用 GPU 0–3、TP=4、BF16、
纯文本、262144 上下文及单序列并发，绑定 `127.0.0.1:18080`。
`qwen3_coder` 解析工具调用。SDK 的 disabled 开关并不足够：本次 Claude Code 2.1.285（SDK 0.2.152）对未知模型
省略 thinking 字段，却默认发送 effort=high，覆盖服务默认模板参数。部署脚本
因此生成并哈希固定关闭思考的模板（只改 generation prefix 的条件），即使请求
传入 enable_thinking=true 也以闭合的 `<think></think>` 前缀开始生成。
同时通过已哈希的 ASGI 中间件在 Anthropic 请求中固定 thinking=disabled 和
enable_thinking=false，使解析器也处于非思考状态；提示词、工具、消息和采样
参数不变。服务日志只记录原始模式字段，不记录认证信息。
采样固定为 temperature=1、top_p=1、top_k=20、presence_penalty=2、
repetition_penalty=1、seed=1337。启动参数、权重/模板哈希、依赖和 GPU 信息
记录在 `.tools/qwen-service/deployment.json`，服务输出写入同目录 `server.log`。

确认服务和独立测试 binary 的 Agent 工具调用链路正常后，在另一终端准备实验：

```bash
.venv/bin/python scripts/prepare_ida_agent_eval.py prepare \
    results/deepseek-v41-flash-pilot results/qwen35-08b-nonthinking-pilot \
    --model qwen3.5-0.8b --base-url http://127.0.0.1:18080 \
    --reference-tree results/deepseek-v41-flash-pilot \
    --deployment .tools/qwen-service/deployment.json
.venv/bin/python scripts/prepare_ida_agent_eval.py check \
    results/qwen35-08b-nonthinking-pilot --resources
.venv/bin/python scripts/prepare_ida_agent_eval.py run \
    results/qwen35-08b-nonthinking-pilot --backend ida-agent@qwen3.5-0.8b
```

参考模式验证旧输入哈希、函数地址和完整清单，复制相同样本；旧实验锁不改写。
本地调用使用占位认证值，不读取 DeepSeek 密钥。预算与前表相同，只有思考模式
在服务模板固定关闭；SDK 仍设置 disabled，但不能依赖它省略 effort。正式失败保留；不会因小模型工具调用失败
而自动更换提示词、重新抽样或择优重试。

对比使用旧实验修正后的 byte_match v8 和相同 GED/type_match 算法。
运行完成后先离线补齐 byte_match overlay 中的 compilable 字段，再生成固定分母
的三方对比。缺失的可编译字段不是 false；独立语法检查与评分修补后的可编译性
应分开报告。下面的离线命令不调用模型：

```bash
PATH="$PWD/.tools/host-gcc-12.3.0/usr/bin:$PWD/.tools/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/bin:$PATH" \
PYTHONPATH="$PWD" DECBENCH_REEVAL_DECOMPILERS=ida-agent@qwen3.5-0.8b \
.venv/bin/python scripts/reeval_bytematch.py results/qwen35-08b-nonthinking-pilot 1
PYTHONPATH="$PWD" .venv/bin/python scripts/finalize_results.py \
    results/qwen35-08b-nonthinking-pilot --render
.venv/bin/python scripts/compare_ida_agent_pilot.py results/qwen35-08b-nonthinking-pilot \
    --reference results/deepseek-v41-flash-pilot
```

均值应同时报告有效分母；缺失不当作零分。耗时需区分冷启动、评测墙钟时间和
逐函数 Agent 耗时；SDK 的美元估价不代表本地 GPU 成本。
这轮结果只保存在本地，不自动发布网站或 HuggingFace 数据集。

### 旧 checkpoint 的失败名称修复

旧驱动仅把成功输出的匿名名称回填成 DWARF 源函数名，`failed_functions`
中的 `sub_<address>` 会被汇总器当作未解析函数过滤。全部成功的旧 DeepSeek
实验不受影响；有失败的 Agent 实验必须核对冻结清单分母。

修复后的驱动会同步回填失败名称。对旧实验，等模型运行结束后执行：

```bash
.venv/bin/python scripts/repair_pilot_failures.py results/qwen35-08b-nonthinking-pilot
PYTHONPATH="$PWD" .venv/bin/python scripts/finalize_results.py results/qwen35-08b-nonthinking-pilot
.venv/bin/python scripts/prepare_ida_agent_eval.py audit \
    results/qwen35-08b-nonthinking-pilot --backend ida-agent@qwen3.5-0.8b
```

修复器校验 binary 哈希、保留成功 C 和指标值，只修复失败/未尝试目标的记账。
原 checkpoint 和首轮汇总保存在 `first-pass-failure-labels/`，变更与哈希写入
`failure-label-repair-provenance.json`，不重新调用模型。原实验锁不改写；
若锁定的是旧驱动，之后 `check/run` 会因驱动代码变化拒绝继续，这是预期保护。

首轮 `results/qwen35-08b-pilot` 因上述模式问题仅作诊断保留。修正后在新目录完整
重跑相同 24 个目标，不合并两轮结果、不择优选取输出。生成比较报告前写入
`mode-verification.json` 记录模板、实际请求和会话审计证据；未验证时报告不得
声称是非思考模式。

## Qwen3.5-4B Thinking 评测

4B 使用同一 24 函数清单和 Agent 预算，选择官方 Thinking 精确代码任务预设：
temperature=0.6、top_p=0.95、top_k=20、min_p=0、presence_penalty=0、
repetition_penalty=1。其余四卡部署参数与 0.8B 相同。使用独立部署和结果目录：

```bash
.venv/bin/python scripts/serve_qwen_pilot.py \
    --model-path /data/home/lxy/models/Qwen/Qwen3.5-4B \
    --served-model-name qwen3.5-4b --thinking enabled \
    --sampling-preset official-thinking-coding --output .tools/qwen-service-4b-thinking
.venv/bin/python scripts/prepare_ida_agent_eval.py prepare \
    results/deepseek-v41-flash-pilot results/qwen35-4b-thinking-pilot \
    --model qwen3.5-4b --base-url http://127.0.0.1:18080 \
    --reference-tree results/deepseek-v41-flash-pilot \
    --deployment .tools/qwen-service-4b-thinking/deployment.json --disable-session-title
.venv/bin/python scripts/prepare_ida_agent_eval.py run \
    results/qwen35-4b-thinking-pilot --backend ida-agent@qwen3.5-4b
```

模板适配两种 Qwen 条件方向，Thinking 模式固定开放的 `<think>` 前缀；
SDK 和服务请求设置 adaptive，不新增独立思考 token 预算。服务固定模板/解析器
的 enable_thinking=true，覆盖请求中的 temperature/top_p/top_k；其余采样参数
由已冻结的服务 generation config 提供。实际请求、模板渲染、解析结果均需预检，
不能只看 SDK 配置或 thinking_tokens 计数。

完成后按前节补齐 byte_match overlay（替换目录和后端名）、finalize，再比较：

```bash
.venv/bin/python scripts/compare_ida_agent_pilot.py results/qwen35-4b-thinking-pilot \
    --reference results/deepseek-v41-flash-pilot \
    --additional results/qwen35-08b-nonthinking-pilot
```

报告必须指出与 0.8B 的模型大小、思考模式、采样参数同时改变，不能将差异单独
归因于参数量。旧结果及锁文件不改写；若检查旧实验时因部署脚本更新出现代码漂移，
不改旧锁绕过。此次评测核验完毕后停止本轮服务，确认端口关闭、四卡显存释放。

4B Thinking 中 SDK 自动标题的结构化生成请求可能长时间占用单序列服务，
使正式任务排队。`--disable-session-title` 通过 CLI 自带
`CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1` 关闭该辅助功能；默认行为保持不变。
这不改变正式任务的提示词、工具或预算，但属于相较旧基线的运行配置差异，
须记入锁文件和报告。首个受标题阻塞影响的未完成轮次整轮归档排除，不能择优合并。
