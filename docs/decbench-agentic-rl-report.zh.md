# 用强化学习训练模型做反编译

课题组阶段报告 · 2026 年 11 月 24 日 · Qwen3.5-4B / DecBench

## 1. 背景：只有编译后的程序，怎样恢复一个函数？

### 从机器指令到可读的 C 代码

程序员用 C 写函数，**编译器**把它翻译成处理器能执行的机器指令。这个过程会丢失信息。举一个简化的例子：程序员写的是 `int successor(int count) { return count + 1; }`。编译并移除符号后，分析者可能只看到某个地址上的几条指令，能判断它们“取输入、加一、返回”，却很难知道作者把函数叫作 `successor`、把参数叫作 `count`。

**反编译**就是从这些指令出发，尝试写回人能读懂、行为与原函数一致的代码。例如 `int sub_401000(int x) { return x + 1; }` 可以表达同样的计算。真实函数还涉及分支、指针和外部调用。IDA 是分析二进制的工具；它的 Hex-Rays 反编译器能给出一份类似 C 的初稿（伪代码）。当初稿中的类型或操作不确定时，分析者可以查看**汇编**，即机器指令的文字表示，逐条核对。

### Agent 做什么，强化学习又发生在哪里？

假设模型接到一道题：“恢复指定地址的函数，把 C 写进文件。”它先请求工具查看伪代码，遇到可疑分支就查汇编，写完文件后读编译器报错，再决定改哪一行。**能根据上一步反馈选择下一步动作的模型，在这里叫作 Agent（智能体）。** 从接题到交付文件的一次完整尝试叫作一条**轨迹**。工具反馈帮助它在这一次尝试里改代码；此时模型参数尚未更新。

**Agentic RL** 把这种多轮做题过程用于强化学习（RL）。项目让模型对同一个函数独立尝试四次，把四个最终文件分别评分。训练算法 GRPO 比较同题四次的相对得分，用这个差异更新模型选择动作的概率。模型没有收到“第二步应该查汇编”的标准答案；训练信号来自整个尝试的结果。因此，一个值得检验的问题是：最后文件得了高分，前面哪些动作真的值得鼓励？

### 本项目具体检验什么？

**Qwen3.5-4B** 是做题的模型；**DecBench** 提供目标函数、工具和评分；**AgentEvolver** 负责组织多次尝试并更新模型。主要分数 `byte_match` 的计算思路是把候选 C 重新编译，再与目标函数的机器指令比较，越接近得分越高。还要分别看文件有没有写出、原始 C 能否编译。指令相似度能自动测量，程序在不同输入下是否表现一致、代码是否容易维护，还需要其他证据。[评分方法](metrics.md)

本次研究比较三种工具交互方案，每组训练十步，再回到同一组固定验证题检查变化。两组的验证均分有所提高，另一组在后测中未能写出文件。要理解这两个结果，先看模型究竟拿到一道什么题，以及环境怎样判定它已经完成。

## 2. 怎样搭建反编译 Agent 环境，并接入 AgentEvolver

我们把“一次函数反编译”做成一个可重复交互的任务。**DecBench 管一个函数的一次尝试**：打开目标二进制、执行模型选择的工具、保存候选 C、给最终文件评分。**AgentEvolver 管怎样尝试和学习**：为同一道题创建多个独立实例，让 Qwen 逐轮选择动作，再把各次尝试的得分用于策略更新。两侧交接的是题目、动作、观察和终局分数。下面以第一轮实验为例说明。模型每轮用 JSON（一种有字段名和值的文本格式）写出工具请求。

### 先定义一个能让模型反复尝试的环境

以地址 `0x40759c` 的函数为例。模型开始时只知道要在 `target.bin` 中恢复这个地址的函数，并把结果写入 `decompiled.c`。环境持有私有任务记录，能按 task_id 找到相应二进制、目标地址和编译条件。每次尝试单独启动一个 worker，使用独立临时目录、IDA 会话和候选文件。同一道题采样四次时，某条轨迹写坏了文件，其他三条仍从各自的初始状态开始。任务与实例初始化（本地 `decbench/rl/agentevolver_env.py`） · worker 的状态与生命周期（本地 `decbench/rl/worker.py`）

### 模型在 DecBench 环境里具体能做什么？

面对一个匿名函数，模型每轮可以选择九种工具中的一种：六种向 IDA 查询目标二进制，三种操作本次尝试的候选文件。下表按模型试图回答的问题排列。IDA 工具在接口中统一带有 `mcp__ida__` 前缀。

| 模型要解决的问题 | 工具与主要参数 | 模型收到什么，环境改变什么 |
|---|---|---|
| 我正在分析哪种二进制？ | `get_metadata()` | 返回文件名、平台与格式、架构与位数、映像基址、函数数量、符号剥离状态。 |
| 这个地址的函数大致在做什么？ | `decompile_function(addr)` | Hex-Rays 返回 C 风格伪代码。模型可以据此起草候选 C；伪代码里推断出的类型和表达式仍需核对。 |
| 某段伪代码对应哪些真实指令？ | `disassemble_function(addr, offset, length)` | 返回逐条汇编指令及地址，可核对分支、访存与调用。`offset` 按指令数翻页，`length` 控制本次读取条数。 |
| 谁调用了这个函数，或谁使用了这个全局地址？ | `get_xrefs_to(addr, offset)` | 查**指向**目标的引用，返回引用发生的位置及所在函数。可从调用者一侧观察参数怎样传入。 |
| 这个函数又调用了谁、访问了哪些全局对象？ | `get_xrefs_from(addr, offset)` | 查**从函数发出**的引用，返回产生引用的指令位置和目标地址或名字。两种引用查询都支持翻页。 |
| 地址里实际存了哪些字节？ | `read_bytes(addr, size)` | 返回十六进制与 ASCII 对照，可查看常量或字符串。默认读 64 字节，单次可请求 1–512 字节。 |
| 我上一轮写出的 C 是什么？ | `Read(file_path)` | 读取当前 `decompiled.c`；尚未写入时返回文件尚无内容的提示。 |
| 我已准备好一版完整函数，怎样交付？ | `Write(file_path, content)` | 用完整内容替换 `decompiled.c`，保存后自动运行编译器语法检查，返回通过信息或诊断。即使有语法错误，文件也会保留供下一轮修改。 |
| 能否只修编译器指出的那一处？ | `Edit(file_path, old_string, new_string)` | 仅当旧文本在文件中恰好出现一次才进行替换，随后自动重新检查。找不到或匹配多处时返回动作错误，模型可以先 Read 再决定怎样修。 |

查询地址可以写成 ELF 十六进制地址，也可以用 IDA 已识别的名称。若 IDA 尚未识别该地址处的函数，任务提示允许在普通反编译或反汇编请求失败后加 `force=true`，在本次尝试的临时 IDA 数据库中建立函数。三个文件工具的操作范围均限于当前 `decompiled.c`。[冻结工具清单](../results/qwen35-data-v1/pilot/tools.json) · 参数校验与执行逻辑（本地 `decbench/rl/worker.py`）

**一轮检查与最终评分由不同事件触发。** Write/Edit 自动返回的是语法诊断，模型可以继续查询、改写或结束。在文本 JSON 基线里，模型发出 `{"finish":true}` 或累计执行到第 12 轮时，环境结束交互；AgentEvolver 随后请求对最后保存的文件计算 byte_match。finish 是结束信号，九种工具中没有供模型主动查询终局得分的操作。环境的 step 与 evaluate（本地 `decbench/rl/agentevolver_env.py`）

这套设计允许模型自行选择查询顺序，也允许它根据反馈改变下一步。一次真实轨迹中，模型先请求 IDA 反编译 `0x40759c`，收到包含 `free(a1);` 的伪代码。它后来在 JSON 调用前加了一句说明，环境返回解析错误；直到第八轮成功 Write，候选文件才被写出。这些决策来自策略，环境负责执行合法请求并如实返回结果。原始轨迹，第 2 条（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/traj_10.jsonl`） · 工具执行和文件评分（本地 `decbench/rl/worker.py`）

### AgentEvolver 如何调用这个环境（BaseEnv 接口）

接入点是 `DecbenchEnv(BaseEnv)`。对框架来说，反编译是一个按 ID 创建、可以反复 step、结束后可以 evaluate 的环境。对 IDA 来说，请求由本地 worker 执行。适配器在二者之间翻译数据：上游通过 EnvService 的环境客户端调用，下游通过 EpisodeClient 的标准输入输出发送逐行 JSON。环境适配器（本地 `decbench/rl/agentevolver_env.py`） · worker 通信桥（本地 `decbench/rl/bridge.py`）

| AgentEvolver 的请求 | DecBench 适配器返回什么 |
|---|---|
| 按 split 枚举任务，选一个 task_id 创建实例 | `get_query_list` 返回冻结清单中的任务 ID。实例初始化时按 ID 查私有记录，启动本轮 worker，并请求 IDA 元数据确认工具可用。训练包装类额外记录项目、划分与训练阶段。 |
| `get_init_state()` | 返回 `state`（system 和 user 消息）与 `info.task_id`。框架据此生成第一条 assistant 动作。 |
| `step(action)` | 从 assistant 的 content 解析工具名和参数，向 worker 发送 execute。返回 `state`（本轮观察）、`reward=0.0` 和 `is_terminated`。格式错误也产生一轮观察，模型可以继续尝试。 |
| `evaluate(params={"sparse": true})`，随后释放实例 | 环境向 worker 请求 score，落盘候选代码与评分元数据，向框架返回一个浮点分数。实例关闭时释放 worker；任务 ID 可用于另起一次独立尝试。 |

### 注册、采样和更新怎样串起来

1. **注册环境类型。** 项目的适配脚本在 AgentEvolver 的环境发现目录 `env_service/environments/decbench/` 放入入口模块，将 `DecbenchTrainingEnv` 暴露为 `DecbenchEnv`。训练配置设置 `env_type: decbench`。实际接入时还修正了注册器只认直接父类的问题，使它能发现继承链 `DecbenchTrainingEnv → DecbenchEnv → BaseEnv`。注册脚本（本地 `scripts/hpc4/bootstrap_qwen35.sh`） · 训练包装类（本地 `scripts/hpc4/training_env.py`） · 注册修复记录（本地 `results/setup/QWEN35_REPORT.md`）
2. **让训练器连接到环境服务。** 同一调度分配内，阶段脚本先启动 `env_service.env_service --env decbench`，把本机服务地址写入 `AE_ENV_URL`；确认服务可访问后才启动 `agentevolver.main_ppo` 并加载 qwen35 配置。模型运行在训练容器，IDA 和评分器运行在独立 worker 的 Python 环境，二者通过上面的环境接口协作。服务启动顺序（本地 `scripts/hpc4/train_qwen35_phase.sh`） · 训练配置（本地 `configs/agentevolver/qwen35.yaml`）
3. **由框架驱动多轮采样。** AgentFlow 用当前消息请求 vLLM 生成动作，保存生成结果，调用 `env.step(instance_id, action)`，把返回的观察追加到本实例历史。下一轮 Qwen 因而能看到上一轮的结果。文本基线把反馈作为 user 消息；原生工具版把调用从说明中分离，按调用 ID 返回 tool 消息。两条路径都把工具实际产生的观察带回生成循环。AgentFlow 采样循环（本地 `.tools/AgentEvolver-qwen35/agentevolver/module/agent_flow/agent_flow.py`） · 原生协议适配（本地 `docs/native-tool-calling.zh.md`）
4. **由框架消费终局奖励。** 任务指定环境评分器 `env`。轨迹结束后，AgentEvolver 的 EnvGrader 调用该实例的 evaluate，将 DecBench 返回的数值作为轨迹得分。一题四条轨迹分别评分，训练器在同题内计算 GRPO 优势，HET actor 用生成 token 的损失掩码更新 Qwen。编译报错能改变模型下一次动作；最终文件得分才进入这次实验的组内奖励计算。EnvGrader（本地 `.tools/AgentEvolver-qwen35/agentevolver/module/task_manager/rewards/env_grader.py`） · [逐步奖励与更新批次](../results/qwen35-supervised-3807371/attempt-6/evidence/batch-rank--1.jsonl)

**接入怎样验收？** 先在独立 worker 上验证真实 IDA 和已知候选代码能得到预期观察与分数；再用真实 Qwen 走一条完整轨迹，对照事件、候选文件与终局评分；最后检查多条采样是否产生奖励差异，以及优化器是否确实更新。项目分别留下了九种工具的运行记录、真实 episode 和四卡更新证据。HPC4 容器、IDA 安装、模型路径与依赖版本集中在复现手册中。[真实工具验收](../results/setup/3803079/ida-check.json) · [模型与训练验收](../results/setup/QWEN35_FINAL_REPORT.md) · HPC4 与 IDA 搭建手册（本地 `docs/agentevolver-hpc4.zh.md`） · Qwen3.5 环境配置（本地 `docs/qwen35-validation.zh.md`）

### 从项目源码到匿名任务

语料版本 3803269 覆盖 25 个 SAILR 和 8 个 CPS 项目，项目声明了 98 种构建组合，62 种构建成功，36 种失败。带调试信息的产物用于对齐来源、函数边界和地址，剥离符号的二进制供模型分析。静态筛选得到 57,116 个候选函数；版本报告中真实工具审计记录为 1,734 项 ready、59 项 blocked。试训使用独立冻结的已审计快照，实际训练池 108 题、固定验证集 32 题。上述数字分别计构建组合、候选、审计状态和实际样本，不能直接以 57,116 为训练集大小。数据按项目隔离并去重，bzip2 和 ChibiOS 留出，malware 项目排除。[版本化语料报告](../results/rl-corpus-v1/versions/3803269/REPORT.md) · 试训数据说明（本地 `docs/qwen35-validation.zh.md`）

每个任务绑定一个二进制、一个 ELF 虚拟地址和一种优化等级。模型看到匿名目标、地址、可用工具和交付路径；私有清单保留项目、原函数名、架构、编译参数及哈希，供评分与事后核查。动作限于环境提供的工具：读取 Hex-Rays 伪代码、反汇编、引用和字节，在 episode 内读写或编辑 `decompiled.c`。写入后可以根据编译诊断继续修正。最终评估读取文件，模型最后一段自然语言不参与文件评分。公开训练题面（本地 `results/qwen35-data-v1/pilot/train.jsonl`） · 私有任务清单（本地 `results/qwen35-data-v1/pilot/tasks.private.json`）

### 一条数据到底包含什么？

每条记录对应某个编译产物中的一个目标函数。训练集和验证集使用相同的字段结构。以训练集第一题为例，模型读到的任务是：

> Recover sub_401f52 at ELF virtual address 0x401f52 in target.bin. Write your C to decompiled.c.

| 存放位置 | 字段 | 例子与作用 |
|---|---|---|
| 公开任务行 | `prompt` | system 消息说明怎样用 IDA、怎样交付文件；user 消息指定匿名函数、ELF 地址和输出文件。模型从这里开始作答。 |
| 公开任务行 | `data_source`、`agent_name`、`ability` | 分别是 `decbench/ida-byte-proxy`、`decbench_ida`、`decompilation`，用于标记数据来源、Agent 与任务类型。 |
| 公开任务行 | `reward_model`、`extra_info` | 评分方式为 `rule`，`ground_truth` 为空字符串；元数据包含 task_id、split、index、environment_version。第一题的 ID 为 `b327587c13553b2979dc477c`。 |
| 私有清单 | 函数与构建信息 | 同一 ID 对应 base-passwd 的 `ask_debconf`，地址 `0x401f52`，x86-64、O0，目标函数长 19 字节。还记录语料、项目划分、编译器及版本、构建参数和源码指纹。 |
| 私有清单与二进制目录 | `original_binary`、`stripped_binary` 及哈希 | 记录原始与剥离符号的二进制路径，供工具和评分器定位、校验目标。源码版本、重复簇等字段用于检查来源和去重。 |

公开行描述任务；模型实际接收其中的提示消息和运行时附加的工具说明。环境按 task_id 找到私有记录。模型输出的 JSON、IDA 返回的伪代码、写出的 C、每轮 token、loss mask 和终局奖励都在 rollout 时产生。一次训练步为同一公开题面采样四次，固定验证每题采样一次。训练行（本地 `results/qwen35-data-v1/pilot/train.jsonl`） · 验证行（本地 `results/qwen35-data-v1/pilot/validation.jsonl`） · [任务导出代码](../decbench/rl/tasks.py)

逐题清单见文末附录。

## 3. 训练方法：三种方案如何交互，怎样从结果中学习？

### 三种方案下，模型怎样写出一个函数？

模型读写文本时会把它拆成小单元，每个单元叫作一个 token。假设模型已经看过 IDA 伪代码，现在要把恢复的函数写入 `decompiled.c`。下面用同一段简化的 C 代码演示三种方案的模型输出。

**文本 JSON 基线**（严格 JSON，3807371）。模型生成一段 JSON 文本，`name` 指定工具，`arguments` 给出文件名和代码。

```json
{"name":"Write","arguments":{"file_path":"decompiled.c","content":"int sub_401000(void) { return 0; }"}}
```

环境解析这段文本，写入文件，再把编译检查结果作为下一轮消息发给模型。模型可以根据报错继续调用 `Edit`。如果在上面这行裸 JSON 前加一句“我来写入文件”，整段文本就无法按 JSON 解析，这一轮也不会执行写入。

**文本 JSON 轨迹对齐版**（Heuristic-A v2，3815284）。模型仍像基线一样输出上面那行 `Write`。假设这次写入后，编译器提示“缺少分号”，模型下一轮用 `Edit` 补上分号，最终文件得了高分。所谓“一条轨迹”，就是从第一次写入、读到报错，到最后修好代码的整段交互。对齐版改了两处，让训练能用上这段经历。

| | 文本 JSON 基线 | 文本 JSON 轨迹对齐版 |
|---|---|---|
| **改动一：让最后的修复也能进入训练** | 从模型第一次回答开始，只保留后续前 4,096 个 token。长篇 IDA 输出和编译报错也占位置。最后的 `Edit` 即使修好了文件，也可能排在截断线之后；训练仍然使用最终文件的高分。 | 初始题面最多占 2,048 个 token，后续多轮交互最多占 14,336 个。每次请求模型生成下一条动作前，按当前上下文计算可用空间；不足 256 个 token 就结束交互并给当前文件评分。这样，已经执行并改变最终得分的 `Edit` 会留在训练样本里。 |
| **改动二：让训练看到模型当时实际读写的内容** | 生成端与训练端使用同一聊天模板，根据对话文本还原模型输入。模型实际处理的是一串数字编号（token ID）；同一段可读文字有时可以由不同的编号序列拼出来。 | 每一轮都保存模型实际收到和生成的编号。下一轮沿用上一轮的原始编号，再接上模型实际看到的工具反馈。推理引擎回传它收到的编号，供训练端逐个核对；训练只对模型写出的部分计算损失。 |

**一次编译报错之后，还能写多长的 Edit？** 对齐版先把模型实际看到的报错加入历史。假设初始提示占 1,800 个 token，当前发给模型的完整前缀占 15,000 个（含本轮 assistant 起始标记）。总窗口还剩 16,384 − 15,000 = 1,384 个；多轮交互预算还剩 14,336 − (15,000 − 1,800) = 1,136 个。取较小的 1,136，再预留 16 个，本轮最多生成 **1,120 个 token**。单轮上限是 4,096；如果算出的可用量不足 256，就结束当前轨迹，用已有文件评分。这个检查发生在模型动笔前，系统无法预知它是否会写出一条完整、合法的 Edit。

训练端还有一道核验：按动作顺序核对生成时的输入前缀、实际输出和环境记录的动作数。模型实际写出的 token 标为 1，作为下一次动作依据的编译报错标为 0；两者都占上下文空间。若已执行轨迹超出训练长度或有动作缺失，构造样本直接报错，避免删掉末尾修改却继续用修好后的文件奖励前面的动作。预算计算与样本核验（本地 `scripts/hpc4/heuristic_runtime.py`）

这两处改动有各自的证据。**基线**的 160 条训练轨迹中有 52 条被截断，47 次可解析的 `Write/Edit` 完全没有进入训练。随后开发对齐版时，**中间试跑 v1** 又发现 64 条预检轨迹中有 8 条在“编号转文字、文字再转编号”后发生变化，因此在首次参数更新前停止。最终的 v2 直接传递原始编号，并通过真实模型的两轮核对。三种方案仍按最终文件计算奖励；本轮实验没有把上述两项改动拆开单独评测。[基线截断审查](../results/setup/qwen35-regression-audit-v1/REPORT.zh.md) · 轨迹预算与训练规则（本地 `docs/heuristic-training.zh.md`） · [v1 到 v2 的修复记录](../results/heuristic-prefix-fix-v2/REPORT.zh.md)

**原生结构化工具调用版**（Native-A，3822719）。模型可以先写一句说明，再用 Qwen 的原生工具标记给出调用：

```text
我来把恢复的函数写入文件。
<tool_call>
<function=Write>
<parameter=file_path>decompiled.c</parameter>
<parameter=content>
int sub_401000(void) { return 0; }
</parameter>
</function>
</tool_call>
```

解析器把第一句放入 `content`，把标记中的工具名和参数转换为 `tool_calls`。环境按其中的 `Write` 执行，再通过调用 ID 把编译反馈关联到这次写入。模型读到对应反馈后，可以继续修改文件。原生协议与输出示例（本地 `tests/test_native_tools.py`）

### 一条轨迹怎样产生训练信号

文本 JSON 基线第 10 步的一条真实轨迹，题面要求从 `target.bin` 的 `0x40759c` 恢复 `sub_40759c`。私有映射对应 kmod 的 `cfg_file_free`（O0）。第一次动作调用反编译工具，IDA 返回的函数体核心是 `free(a1);`。模型随后在 JSON 前加了一句英文解释，解析器拒绝该轮动作。第八次动作成功写入文件。全程 12 次动作仅上述反编译和写入两次合法，最终文件仍获 1.0 分。当步原始轨迹，第 2 条（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/traj_10.jsonl`） · [逐动作审查](../results/setup/qwen35-regression-audit-v1/REPORT.zh.md)

1. **生成与交互。** 每个函数建立四条独立轨迹。工具返回作为新观察送回模型；所有普通交互步奖励为零。达到回合上限或显式结束后，环境请求最终评分。
2. **评分。** byte-match-v8-proxy-v1 使用确定性修复、重编译与目标机器码比较；无法精确匹配时可根据归一化汇编相似度给部分分。无输出文件得零分。评分元数据中的 exact_match、原始文件独立编译、评分器修复后可编译分别统计；单看奖励 1.0 也不足以判定行为等价。[指标说明](metrics.md) · [奖励路径与实例](../results/setup/heuristic-3815284-output-audit/REPORT.zh.md)
3. **同题比较。** 用同一函数四次终局分数计算组内标准化优势。四次得分相同，该题无法提供相对偏好；四个不同函数各自归组。文本 JSON 基线预检 8 个任务组中有 7 组出现奖励差异；正式 step 1 四组都有差异，step 2 只有两组。[预检记录](../results/qwen35-supervised-3807371/attempt-6/evidence/preflight-rank--1.jsonl) · [逐步 batch](../results/qwen35-supervised-3807371/attempt-6/evidence/batch-rank--1.jsonl)
4. **参数更新。** 将轨迹优势分配给保留的 assistant 动作 token，遮蔽提示、工具观察及 padding。训练器计算旧策略和参考策略的 log probability，HET actor 计算裁剪策略损失和 KL 正则，反向传播后更新参数。步骤 1–4 重复十次，四个 rank 各记录十次同步优化器更新。

### 采样和优化配置

| 参数 | 文本 JSON 基线 | 文本 JSON 轨迹对齐版 | 原生结构化工具调用版 |
|---|---|---|---|
| 动作与观察 | 每轮一个文本 JSON，观察作为 user 消息 | 文本 JSON，按原始 token 继续多轮生成 | 工具 schema、结构化 tool_calls、按调用 ID 返回 tool 消息 |
| 训练样本 prompt / response 上限 | 12,288 / 4,096 | 2,048 / 14,336 | 4,096 / 12,288 |
| rollout 预算 | 三组均为 16,384 总上下文，配置 prompt / response 为 12,288 / 4,096，每条最多 12 次动作 | 同左 | 同左 |
| 信号分配 | 终局 GRPO | A 组终局 GRPO，记录动作和私有中间评分 | A 组终局 GRPO，原生工具边界对齐 token |
| 固定验证时点 | 0、10 | 0、1、2、5、10 | 0、1、2、5、10 |

三组配置均取 seed 1337、每步 4 题、每题 4 次采样。训练生成使用温度 0.8、top-p 0.95、top-k 20，验证每题一次贪心生成。推理张量并行度 2，训练用 FSDP2、梯度检查点和 CPU offload；学习率 1e-6，配置的 PPO mini-batch 为 4，每 GPU micro-batch 为 1。文本 JSON 基线最终展开配置还记录了单个 PPO epoch、无 warmup、梯度裁剪 1.0、比率裁剪下侧 0.20 / 上侧 0.28、参考策略 KL 系数 0.001、熵系数 0。训练池中的题目数、每次更新的函数数、单卡 micro-batch 是三个不同单位。文本 JSON 基线最终配置（本地 `results/qwen35-supervised-3807371/attempt-6/resolved-config.yaml`） · 文本 JSON 轨迹对齐版配置（本地 `configs/agentevolver/heuristic.yaml`） · 原生结构化工具调用版配置（本地 `configs/agentevolver/native.yaml`）

### 从预检到恢复

文本 JSON 基线有效 attempt 先做初始化，再做 8×4 奖励预检（约 24 分钟）和固定 32 题基线（约 25 分钟）。前五次更新与保存约 70 分钟。随后退出，启动新的 TaskRunner 与四个 worker，从 step 5 恢复，核对模型与优化器采样指纹、优化器计数、RNG、学习率与 dataloader 状态。后五次更新约 78 分钟，最终验证约 30 分钟。在有完整分项计时的 8 步中，rollout 平均 14.04 分钟，占这些步耗时的 92.2%；actor 更新平均 56.78 秒。rollout 含生成、工具与评分，不能把这 92.2% 全部算作 IDA 耗时。[训练与恢复验收](../results/setup/QWEN35_FINAL_REPORT.md) · [阶段计时及覆盖范围](../results/setup/training-timing-v1/REPORT.zh.md)

## 4. 训练效果：模型交付的代码有改善吗？

下面比较各方案训练前（step 0）和十次更新后（step 10）的表现。固定验证集有 32 个函数，每题作答一次，评分取 32 题平均；无输出计零分。表中“评分器可编译”允许确定性修复，“精确匹配”统计评分器标记为精确匹配的任务数。工具成功率按交互轮次计算。

| 训练方案 | 全局更新 | 固定验证集平均 byte_match，训练前 → step 10 | 组内增量 | 评分器可编译 /32 | 精确匹配 /32 | 工具成功轮次占比 | 主作业墙钟 | GPU·小时 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| [文本 JSON 基线](../results/qwen35-supervised-3807371/attempt-6/acceptance.json) | 10 | 0.3502 → 0.0000 | -0.3502 | 17 → 0 | 3 → 0 | 81.96% → 9.90% | 5:57:11 | 23.81 |
| [文本 JSON 轨迹对齐版](../results/heuristic-3815284/attempt-1/acceptance.json) | 10 | 0.2769 → 0.4881 | +0.2112 | 15 → 22 | 2 → 4 | 85.01% → 80.56% | 5:42:55 | 22.86 |
| [原生结构化工具调用版](../results/native-3822719/attempt-3/acceptance.json) | 10 | 0.4942 → 0.5421 | +0.0479 | 28 → 28 | 3 → 4 | 97.34% → 99.67% | 7:10:43 | 28.71 |

三项主作业都用 4 张 GPU，共 **75.39 GPU·小时**（按未舍入的秒数求和）。墙钟含分配内的预检、验证、恢复、重试，不含排队或另行提交的准备作业。文本 JSON 基线的成功 attempt 约 4 小时，整项作业近 6 小时。三组以各自的 step 0 为起点：原生结构化工具调用版在训练前就有 28 题可编译，文本 JSON 轨迹对齐版只有 15 题。前者终点最高，后者自身增幅最大。协议、模板和轨迹构造同时发生过变化，横向差值无法单独估计某一次改动的收益。[文本 JSON 基线计时](../results/setup/training-timing-v1/REPORT.zh.md) · [原生结构化工具调用版作业总结](../results/native-3822719/FINAL.zh.md)

### 中间验证与逐题变化

下表列出后两种方案的全部已记录验证时点。每个时点使用 32 题。写出、原始可编译、修复后可编译的分母均为任务数；总表中的工具成功率来自 acceptance 的 tool_turn_success_rate，分母为交互轮次。文本 JSON 基线只在两个端点评估，中间步无固定验证观测。[文本 JSON 轨迹对齐版历史](../results/heuristic-3815284/attempt-1/quality-history.json) · [原生结构化工具调用版历史](../results/native-3822719/attempt-3/quality-history.json)

| 方案 | Step | 平均 byte_match | 有输出 /32 | 原始可编译 /32 | 评分器可编译 /32 |
|---|---:|---:|---:|---:|---:|
| 文本 JSON 轨迹对齐版 | 0 | 0.2769 | 24 | 11 | 15 |
| 文本 JSON 轨迹对齐版 | 1 | 0.2531 | 26 | 12 | 16 |
| 文本 JSON 轨迹对齐版 | 2 | 0.3805 | 28 | 14 | 22 |
| 文本 JSON 轨迹对齐版 | 5 | 0.4404 | 30 | 16 | 23 |
| 文本 JSON 轨迹对齐版 | 10 | 0.4881 | 31 | 17 | 22 |
| 原生结构化工具调用版 | 0 | 0.4942 | 31 | 22 | 28 |
| 原生结构化工具调用版 | 1 | 0.4410 | 29 | 25 | 26 |
| 原生结构化工具调用版 | 2 | 0.4585 | 28 | 25 | 26 |
| 原生结构化工具调用版 | 5 | 0.5201 | 31 | 28 | 28 |
| 原生结构化工具调用版 | 10 | 0.5421 | 31 | 27 | 28 |

**文本 JSON 基线的后测失败发生在交付环节。** 基线有 9/32 题未写出文件，到 step 10 为 32/32。成功 Write 调用从 31 次变为 0 次；后测 346 次非法动作中有 345 次在 JSON 首字符处解析失败。全部轨迹的第一轮工具事件成功，之后合计只有 6 次成功事件。零分能定位交互和文件交付失败；没有候选文件供进一步比较其 C 语义。[后测诊断](../results/setup/qwen35-regression-audit-v1/REPORT.zh.md)

**文本 JSON 轨迹对齐版的早期改善主要来自原先零分的任务。** 到 step 5，原先零分的 17 题中有 9 题转为正分，对均值贡献 +0.1741；原先正分的 15 题净贡献 −0.0106，两项合计 +0.1635。到 step 10，均值进一步提高，工具成功率却低于基线。以 gyroInitFilterBiquadRCFIR2 为例，step 0 的原始代码通过编译、得 0.1324；step 5 保留了 IDA 风格类型，独立编译失败，评分器经两轮修复后给 0.35。同时，候选也可能纠正了函数指针赋值。这个配对样例同时暴露了修复带来的得分差异和逐题人工检查的必要性。[输出与源代码审查](../results/setup/heuristic-3815284-output-audit/REPORT.zh.md)

**原生结构化工具调用版的工具调用在基线就相对稳定。** 到 step 10，原始可编译由 22 增至 27，修复后可编译仍是 28，平均分上升 0.047916。逐题配对有 11 题上升、13 题下降、8 题持平，均值反映了变化幅度；提高的任务数没有占多数。step 1 均值曾降至 0.4410，仅看终点会漏掉这段下降。单一种子和 32 题的观测不足以确定跨种子稳定性。[最终验收与配对汇总](../results/native-3822719/FINAL.zh.md)

## 5. 故障、修复和仍待验证的问题

| 现象 | 如何定位 | 采取的措施与验证结果 |
|---|---|---|
| 环境注册、FSDP2 初始化和 vLLM 拓扑依次失败 | 注册器只查直接父类；Transformers 5 的模块集合破坏旧列表假设；隔离的 Ray worker 触发本地 GPU 数检查 | 在隔离副本中改为子类检查、兼容集合、声明 external_launcher 拓扑；真实模型随后完成多轮 IDA 交互及四卡更新。运行记录（本地 `results/setup/QWEN35_REPORT.md`） |
| 文本 JSON 对额外说明敏感 | 合法 JSON 前的自然语言可使整轮解析失败，后测成功写入归零 | 原生结构化工具调用版改用模型模板注入工具 schema、vLLM qwen3_coder parser，分开 content 与 tool_calls，通过 tool_call_id 关联观察；实际模型、工具执行和固定验证均有记录。两轮的差异还包含模板和训练样本变化。原生协议（本地 `docs/native-tool-calling.zh.md`） |
| 文本 JSON 基线的交互上下文与训练截断不一致 | 从第一条 assistant 消息开始累计 response，后续工具观察虽被 mask 仍占长度。回放 52/160 条被截断；372 次可解析 Write/Edit 中，47 次完全未进入 loss、13 次部分保留 | 后两版分别配置训练样本的起始 prompt 与多轮 response 预算，保留生成 token、观察边界及 mask，并做四卡 16K 容量检查。容量通过证明特定长度可训练；改进幅度仍需同协议对照。[截断审查](../results/setup/qwen35-regression-audit-v1/REPORT.zh.md) · 轨迹构造（本地 `docs/heuristic-training.zh.md`） |
| 轨迹对齐前的试跑（Heuristic-A v1）预检后未能更新 | 64 条预检中有 8 条 decode 后再 encode 改变 token 序列，严格前缀检查触发 | 轨迹对齐版把原始 token ID 直接交回 vLLM，服务端回传实际 prompt ID，客户端再次核对。真实两轮生成与 27 项测试通过，替代作业完成十步。[前缀修复记录](../results/heuristic-prefix-fix-v2/REPORT.zh.md) |
| 原生结构化工具调用版的布尔参数、截断调用导致整批异常 | 前两次 attempt 揭示解析器对带空格布尔值的处理不一致 | 只接受明确字面值，残缺或歧义调用不执行，模型协议错误与基础设施失败分别处理。attempt-3 通过 54 项测试、10 种真实工具配置、四卡容量及优化器验收。[原生运行总结](../results/native-3822719/FINAL.zh.md) |
| 高分文件可与多次非法动作共存 | 文本 JSON 基线的 54 条正优势轨迹中有 48 条包含进入 loss 的非法动作，正优势有效 token 约 44.3% 来自非法动作（文本回放估计） | 后两种方案 都保留终局 GRPO。原生协议提高了调用成功率，如何将奖励归给正确动作仍需独立实验；正优势计数也无法确定净梯度方向。[训练回放](../results/setup/qwen35-regression-audit-v1/REPORT.zh.md) |

## 6. 后续研究的优先顺序

| 优先级与假设 | 受控对照与观测 | 哪些结果支持或削弱假设 |
|---|---|---|
| 1 · 动作级信用分配能改善交互，同时保住文件质量 | 在已验收的原生协议上用同一初始模型、任务顺序、上下文、采样、种子和 GPU 预算比较 A/B/C/D。A 广播终局优势；B 约束非法动作的优势；C 为真正改写代码带来的私有评分进展分配优势；D 结合 B、C。记录非法动作进入正优势的 token 比例、成功写出、原始编译与固定集 byte_match | 若 B/D 降低非法正优势占比，且配对任务的文件质量随之改善，支持协议相关信用分配假设。若仅格式变好、文件得分下降，应报告两类目标的取舍。已有十步成绩只属于 A。四组信号定义（本地 `docs/heuristic-training.zh.md`） |
| 2 · 保留产生最终产物的动作能改善学习效率 | 先离线在同一批原始 token 上重建两种 response 预算的 mask，统计完整、部分和完全缺失的 Write/Edit，按轨迹长度分层。再在同一原生协议下只改训练保留预算，控制 rollout 上限、任务和训练步数，另计有效 token 与 GPU·小时 | 预期先提高末段 Write/Edit 的保留率，再改善固定集原始编译或得分。若覆盖率提高而多种子质量持平，则可确认样本构造改善，策略收益仍缺证据。 |
| 3 · 代理分改善能否迁移到独立程序行为 | 冻结方案后使用项目级留出集，保留基线与相同预算的 checkpoint；对具备可信测试和可隔离执行条件的非恶意函数做差分测试，记录可测试覆盖率。另报结构与类型恢复、人工盲评可读性、原始编译及修复后得分 | 以函数为配对单位计算差值和 bootstrap 区间，多种子分别报告。若只在修复后的 byte_match 上涨，而独立测试或可维护性未改善，应将结论限定于代理指标。 |

下一轮先复用原生结构化工具调用版的固定验证基线，同时核查实际送入优化器的动作边界；扩大任务池前先单列构建缺口、可测试函数比例与失败原因。多轮生成目前是主要时间开销，比较方案时并列报告更新步数、有效训练 token、实际 GPU·小时和评估成本。

## 附录：复核和复现入口

从环境与数据锁开始，依次检查真实工具路径、模型与 tokenizer、冻结题集、预检奖励分布、逐 rank 优化器记录、恢复记录和固定验证。文本 JSON 基线作业使用 HPC4 启动与验收手册（本地 `docs/qwen35-validation.zh.md`），后两轮分别使用 文本 JSON 轨迹对齐版训练手册（本地 `docs/heuristic-training.zh.md`） 和 原生工具手册（本地 `docs/native-tool-calling.zh.md`）。历史验收表示当时在新进程中成功恢复；后续按授权清理了三组 step 5/10 的 24 个优化器分片，保留模型权重与验证证据。现存 checkpoint 可用于权重评估，精确续训需完整优化器状态。[检查点保留清单](../results/storage-audit-20261107/OPTIMIZER-CLEANUP.zh.md)

### 训练集和验证集的逐题清单

<details>
<summary>展开训练集全部 108 条样本（按导出顺序）</summary>

| index | task_id | 项目 | 原函数 | ELF 地址 | 架构 | 优化等级 | 函数字节数 |
|---:|---|---|---|---|---|---|---:|
| 0 | `b327587c13553b2979dc477c` | base-passwd | `ask_debconf` | `0x401f52` | x86-64 | O0 | 19 |
| 1 | `c0cc65c577b7e4ea3bc7f90f` | bash | `internal_cfree` | `0x5076c4` | x86-64 | O0 | 52 |
| 2 | `53fc88ca30286e6e4800eb19` | coreutils | `ximalloc` | `0x40734f` | x86-64 | O0 | 34 |
| 3 | `9553340b8f06c62de03a20d3` | cronie | `env_init` | `0x406316` | x86-64 | O0 | 46 |
| 4 | `3dc13b710bed78f155107462` | dash | `yyerror` | `0x4023d8` | x86-64 | O0 | 41 |
| 5 | `6ac0b594df9f5853722f9823` | diffutils | `xmmalloca` | `0x4187f1` | x86-64 | O0 | 46 |
| 6 | `7a2fbefe22004e36b99f836c` | findutils | `parse_ignore_race` | `0x41239e` | x86-64 | O0 | 52 |
| 7 | `2b2de0a29ad4fea0e8cdab81` | freertos | `vPortSetupTimerInterrupt` | `0x21bc` | thumb | O2 | 22 |
| 8 | `fd0036db346083de67d0f7e0` | grep | `null_action` | `0x40d030` | x86-64 | O0 | 10 |
| 9 | `b03fbb083dc3e2bb4a11b4cc` | gzip | `gettime` | `0x40edcc` | x86-64 | O0 | 32 |
| 10 | `6f14ff55cb692b5d3e8269c6` | kmod | `cfg_file_free` | `0x40759c` | x86-64 | O0 | 27 |
| 11 | `a2975409814e091eeec23429` | openssh-portable | `sshpkt_get_end` | `0x7e920` | x86-64 | O0 | 50 |
| 12 | `e93baffe6e6ab90a28c234b9` | shadow | `log_gpasswd_failure_system` | `0x40343e` | x86-64 | O0 | 25 |
| 13 | `d63748f64b34020164d2a571` | sysvinit | `usage` | `0x4037f3` | x86-64 | O0 | 35 |
| 14 | `cf50f3d18b7c8d2eb567cc46` | base-passwd | `unlock_files` | `0x403ac6` | x86-64 | O0 | 69 |
| 15 | `538f83aee9b3661b21c849d2` | bash | `_rl_keyseq_chain_dispose` | `0x4d7d06` | x86-64 | O0 | 66 |
| 16 | `e7bc111b18b6e649594c7b7f` | coreutils | `xalloc` | `0x400f9d` | x86-64 | O0 | 78 |
| 17 | `3a71829f398b392c50571827` | cronie | `job_runqueue` | `0x403ee2` | x86-64 | O0 | 127 |
| 18 | `bb1eaba73afd8ab7c8878d54` | dash | `makename` | `0x40f694` | x86-64 | O0 | 80 |
| 19 | `a8efcd5d2c845f4af8f0cf68` | diffutils | `stackoverflow_deinstall_handler` | `0x404624` | x86-64 | O0 | 113 |
| 20 | `f27a7b28a1e847e263284e81` | findutils | `traverse_tree` | `0x40ab14` | x86-64 | O0 | 116 |
| 21 | `392e0247098120102a0fb116` | freertos | `prvCheckTasksWaitingTermination` | `0x4f8` | thumb | O2 | 132 |
| 22 | `0294460b6a928a1d5fe28725` | grep | `sigsegv_leave_handler` | `0x4358a9` | x86-64 | O0 | 57 |
| 23 | `5b13ee57a9138764ea8d56a1` | gzip | `write_buffer` | `0x40bf1d` | x86-64 | O0 | 54 |
| 24 | `78e45f0b3f323c2b69fa4228` | kmod | `rmmod_all` | `0x4050d3` | x86-64 | O0 | 105 |
| 25 | `e53f03e791280754c943e358` | openssh-portable | `ssh_krl_init` | `0xa0dbb` | x86-64 | O0 | 111 |
| 26 | `5305ab17a8af46627500db78` | shadow | `is_owner` | `0x404d99` | x86-64 | O0 | 119 |
| 27 | `547504eee7ae6e159c4eb599` | sysvinit | `init_freeenv` | `0x404077` | x86-64 | O0 | 106 |
| 28 | `6e719f8266280b1700f3c22f` | base-passwd | `xasprintf` | `0x400fd5` | x86-64 | O0 | 242 |
| 29 | `9e9eb9a44bd91ab181757c5a` | bash | `popexp` | `0x45174f` | x86-64 | O0 | 292 |
| 30 | `dfffa1fba8a773632adb0876` | coreutils | `any_live_files` | `0x404b26` | x86-64 | O0 | 170 |
| 31 | `818ee077995a1af05cd808ac` | cronie | `set_element` | `0x4069ee` | x86-64 | O0 | 159 |
| 32 | `3862b318f74d2df2428f20c6` | dash | `parse_command_args` | `0x404703` | x86-64 | O0 | 327 |
| 33 | `d24d382e0432d6e8281011d0` | diffutils | `prepare_text` | `0x40bcea` | x86-64 | O0 | 324 |
| 34 | `c8b39cb76a119aee812529c0` | findutils | `issue_loop_warning` | `0x4036c4` | x86-64 | O0 | 216 |
| 35 | `7049e10a2b93870028e62bf6` | freertos | `printi` | `0x2ce4` | thumb | O2 | 200 |
| 36 | `ff37dd19f413995e5b0886ef` | grep | `fts_palloc` | `0x41aaea` | x86-64 | O0 | 205 |
| 37 | `272bd8731231cc05e83fb723` | gzip | `update_timespec` | `0x40dda5` | x86-64 | O0 | 297 |
| 38 | `105dacbac526557ddb2b0566` | kmod | `depmod_init` | `0x407e50` | x86-64 | O0 | 278 |
| 39 | `f0d02b80d5a9d3f5d7970794` | openssh-portable | `deserialise_nullable_string` | `0x28a09` | x86-64 | O0 | 150 |
| 40 | `84104e27ee83fbb86d21fd22` | shadow | `resolve_hostname` | `0x404f49` | x86-64 | O0 | 199 |
| 41 | `85ff22657bb060b3241aa731` | sysvinit | `console_open` | `0x4034bb` | x86-64 | O0 | 156 |
| 42 | `a5eef4043c9c5ea290ddc846` | base-passwd | `read_shadow` | `0x401bb0` | x86-64 | O0 | 368 |
| 43 | `a85dc6a06d8146f8a2cd1406` | bash | `mkseq` | `0x48d938` | x86-64 | O0 | 1208 |
| 44 | `118667f444f286d3423a0f97` | coreutils | `simple_strtod_float` | `0x402118` | x86-64 | O0 | 397 |
| 45 | `191b20ef11443bb894a91883` | cronie | `load_database` | `0x403438` | x86-64 | O0 | 1109 |
| 46 | `961622e52f02836d16800a71` | dash | `command` | `0x40ed2b` | x86-64 | O0 | 1735 |
| 47 | `7a0d1f2b40c604e5d355d08c` | diffutils | `get_funky_string` | `0x40dcb8` | x86-64 | O0 | 844 |
| 48 | `497dd98689e31e182060e4a5` | findutils | `usage` | `0x40a315` | x86-64 | O0 | 445 |
| 49 | `43d2f4c5d85abd5703ad0ec0` | freertos | `pvPortMalloc` | `0x1d2c` | thumb | O2 | 480 |
| 50 | `9cfe95eaf17be63f39b50ec6` | grep | `acexec_trans` | `0x40bc7c` | x86-64 | O0 | 1048 |
| 51 | `4b4672921aaf97ae030847da` | gzip | `do_list` | `0x405b6d` | x86-64 | O0 | 943 |
| 52 | `5e45880dec66e1fef77d2876` | kmod | `index_write` | `0x406a73` | x86-64 | O0 | 341 |
| 53 | `e8e2fb04f338ed9b13d5f600` | openssh-portable | `log_init` | `0xf10c` | x86-64 | O0 | 425 |
| 54 | `a2b7db7a284e190c45f63057` | shadow | `open_files` | `0x407177` | x86-64 | O0 | 1083 |
| 55 | `a8cdc94313971e3583328b0e` | sysvinit | `wall` | `0x401ad1` | x86-64 | O0 | 1180 |
| 56 | `89d7bc5fbd91a4e90a700908` | base-passwd | `usage` | `0x402030` | x86-64 | O2 | 47 |
| 57 | `7dd46e907eef84956b4a4804` | bash | `list_reverse` | `0x481d30` | x86-64 | O2 | 34 |
| 58 | `b4a45fbb260e99bcb545446d` | coreutils | `xcharalloc` | `0x4081f0` | x86-64 | O2 | 24 |
| 59 | `68d62e6751d2e112bb298a67` | cronie | `free_entry` | `0x406b00` | x86-64 | O2 | 40 |
| 60 | `e8ac0df622512fa2e449d1ba` | dash | `savestr` | `0x40a510` | x86-64 | O2 | 29 |
| 61 | `776a072bb437e49506f7cf48` | diffutils | `print_normal_script` | `0x40a5f0` | x86-64 | O2 | 15 |
| 62 | `187f6b20b96087daffe1cbd2` | findutils | `get_eval_tree` | `0x406a40` | x86-64 | O2 | 8 |
| 63 | `423d825d0af60c2eaf96b3e9` | grep | `compare` | `0x40a900` | x86-64 | O2 | 23 |
| 64 | `57dfd5e0bc5993b2a9272ddd` | gzip | `abort_gzip` | `0x406070` | x86-64 | O2 | 21 |
| 65 | `9db2c19d7ca15621bc5122d1` | kmod | `mod_cmp` | `0x405600` | x86-64 | O2 | 13 |
| 66 | `93dbddc76d22301310ee2c0c` | openssh-portable | `sshkey_sig_details_free` | `0x22310` | x86-64 | O2 | 10 |
| 67 | `13820dd97074aa9aa2c5f42f` | shadow | `catch_signals` | `0x401a20` | x86-64 | O2 | 14 |
| 68 | `7c71820028691b0ad5d940c8` | sysvinit | `int_handler` | `0x401eb0` | x86-64 | O2 | 48 |
| 69 | `86d58bb2824cd037d60a72c0` | base-passwd | `xmalloc` | `0x4012e0` | x86-64 | O2 | 58 |
| 70 | `26dfecc3ab3b211db1ff5974` | bash | `sh_ttyerror` | `0x48bb00` | x86-64 | O2 | 76 |
| 71 | `8e836c6937bb7d0a0984ec0b` | coreutils | `ximemdup0` | `0x404560` | x86-64 | O2 | 56 |
| 72 | `b5937feb1ed1f2ac33b4bd2b` | cronie | `cron_change_groups` | `0x405b40` | x86-64 | O2 | 108 |
| 73 | `0ad321ecf004ece5972aa802` | dash | `pushredir` | `0x40ed20` | x86-64 | O2 | 68 |
| 74 | `154180a63d24cfaecb0ca768` | diffutils | `mmalloca` | `0x408770` | x86-64 | O2 | 65 |
| 75 | `d25ae8b548d615920a95b1ed` | findutils | `i_ring_push` | `0x415f00` | x86-64 | O2 | 53 |
| 76 | `b2c276090a562fa288869e5f` | grep | `fetch_wc` | `0x40a9b0` | x86-64 | O2 | 57 |
| 77 | `789f57ebb2dd8f0299f8580c` | gzip | `warning` | `0x40aa70` | x86-64 | O2 | 109 |
| 78 | `de638dfb696caabfc5683292` | kmod | `mod_free` | `0x405dd0` | x86-64 | O2 | 93 |
| 79 | `844350895167df4613c34d7d` | openssh-portable | `sshbuf_poke_u16` | `0x3d010` | x86-64 | O2 | 88 |
| 80 | `f9a80ecd7d87dd53b0a7e1a7` | shadow | `shell_is_listed` | `0x402d20` | x86-64 | O2 | 59 |
| 81 | `649ea87518c57da7cd1da906` | sysvinit | `hdflush` | `0x4021e0` | x86-64 | O2 | 123 |
| 82 | `0456ef38a2dd012693f971a3` | base-passwd | `replace_file` | `0x403360` | x86-64 | O2 | 281 |
| 83 | `e581595a60349651bacb33fb` | bash | `expr_bind_array_element` | `0x4480a0` | x86-64 | O2 | 169 |
| 84 | `3bd4daa358afd1e94b967b22` | coreutils | `write_zeros` | `0x404340` | x86-64 | O2 | 162 |
| 85 | `100a8980639f5c65914d5a1f` | cronie | `log_it` | `0x4060b0` | x86-64 | O2 | 269 |
| 86 | `acf673e30d1088b1bc69e75a` | dash | `expandstr` | `0x40db80` | x86-64 | O2 | 303 |
| 87 | `7d8fc2c633d39582406955f8` | diffutils | `c_stack_action` | `0x403a20` | x86-64 | O2 | 146 |
| 88 | `8c3dc1c731b9fb727c5285fe` | findutils | `do_complete_pending_execdirs` | `0x4083b0` | x86-64 | O2 | 210 |
| 89 | `3db27b760caafd81b63702f0` | grep | `treefails` | `0x4080c0` | x86-64 | O2 | 196 |
| 90 | `3a60ebf94e716b7db2e19bfd` | gzip | `flush_window` | `0x40ad10` | x86-64 | O2 | 153 |
| 91 | `ccfbca58277fe96e4dee0250` | kmod | `kmod_help` | `0x402550` | x86-64 | O2 | 158 |
| 92 | `32e91a021b5c7c3085bb4762` | openssh-portable | `sshpkt_disconnect` | `0x55cd0` | x86-64 | O2 | 334 |
| 93 | `25381a4890c26787d54eea21` | shadow | `usage` | `0x402c70` | x86-64 | O2 | 167 |
| 94 | `8c211d472a17766b1e62a0d8` | sysvinit | `donologin` | `0x402ca0` | x86-64 | O2 | 164 |
| 95 | `0b398ee458191cf3e83e34b0` | base-passwd | `process_old_entries` | `0x402450` | x86-64 | O2 | 392 |
| 96 | `ddad7413c3d1e28c830596f4` | bash | `rl_vi_redo` | `0x4b53c0` | x86-64 | O2 | 681 |
| 97 | `7b69e236e4bf645b2857fb2e` | coreutils | `base32_encode` | `0x402350` | x86-64 | O2 | 603 |
| 98 | `504362913777db208fb1c3c1` | cronie | `cron_set_job_security_context` | `0x404070` | x86-64 | O2 | 402 |
| 99 | `bafdcb4f7108eca0a7f4e83d` | dash | `evaltree` | `0x4036f0` | x86-64 | O2 | 598 |
| 100 | `f3d0a427f560b08b2e711ab7` | diffutils | `str_cd_iconv` | `0x40a910` | x86-64 | O2 | 469 |
| 101 | `8496fe2957eacc8d20bf2a9a` | findutils | `qmark_chars` | `0x410ce0` | x86-64 | O2 | 427 |
| 102 | `87d9c042e97147fb0af240ef` | grep | `quotearg_n_options` | `0x417520` | x86-64 | O2 | 462 |
| 103 | `8f21518d1ec0877c95c908c6` | gzip | `inflate_codes` | `0x406090` | x86-64 | O2 | 1244 |
| 104 | `1bc0b326792172272ff10182` | kmod | `cfg_files_insert_sorted` | `0x405bd0` | x86-64 | O2 | 503 |
| 105 | `bddd8175c5a27fc65ab68453` | shadow | `login_access` | `0x4048f0` | x86-64 | O2 | 1013 |
| 106 | `ba8a43cc2b2defca3027b7c9` | sysvinit | `init_main` | `0x4068f0` | x86-64 | O2 | 3165 |
| 107 | `d19f6909c44a4ca102f609b7` | base-passwd | `usage` | `0x401d60` | x86-64 | O2-noinline | 47 |

</details>

<details>
<summary>展开验证集全部 32 条样本（按导出顺序）</summary>

| index | task_id | 项目 | 原函数 | ELF 地址 | 架构 | 优化等级 | 函数字节数 |
|---:|---|---|---|---|---|---|---:|
| 108 | `88fdc180c1fd1e2d248c5046` | cleanflight | `oledResync` | `0x802c5de` | thumb | O0 | 2 |
| 109 | `1618ca3d2cda005286bf0664` | e2fsprogs | `dict_set_cmp_context` | `0x44dc7a` | x86-64 | O0 | 27 |
| 110 | `b50decd00dfb54a133a38a74` | libexpat | `nopProcessingInstruction` | `0x402bd0` | x86-64 | O0 | 19 |
| 111 | `f05476982b2c5a76cd40b31e` | libopencm3 | `adc_read_regular` | `0x80004a2` | thumb | O0 | 26 |
| 112 | `413480b27f20b07a1b9657f1` | tar | `name_term` | `0x422c7a` | x86-64 | O0 | 22 |
| 113 | `4a03f6011be3fb02c0c59609` | cleanflight | `serializeDataflashSummaryReply` | `0x80105b8` | thumb | O0 | 58 |
| 114 | `3a3a0401f6a5c9c03d72e447` | e2fsprogs | `reset_com_err_hook` | `0x48f97f` | x86-64 | O0 | 32 |
| 115 | `b661a0955b55e9b577e30d9d` | libexpat | `unknownEncodingConvert` | `0x403680` | x86-64 | O0 | 38 |
| 116 | `d6ec3ba5b3bdcc03d6c62029` | libopencm3 | `dac_set_waveform_generation` | `0x80007ce` | thumb | O0 | 128 |
| 117 | `c06bc0da0da620b18b7e81c2` | tar | `sys_compare_gid` | `0x4286fd` | x86-64 | O0 | 33 |
| 118 | `c317e6f3a04eff104df203e1` | cleanflight | `dumpPgValue` | `0x801cb00` | thumb | O0 | 132 |
| 119 | `0609ac295ee74ec00fdff28c` | e2fsprogs | `ext2fs_blocks_count` | `0x4531e6` | x86-64 | O0 | 71 |
| 120 | `2addcaf8ae43a88cfff060bc` | libexpat | `externalEntityRefStream` | `0x404aa7` | x86-64 | O0 | 153 |
| 121 | `85fb9a556a73e62cd8003a6b` | libopencm3 | `rcc_osc_on` | `0x8000cf8` | thumb | O0 | 176 |
| 122 | `68730fbf90d3a67edaf05533` | tar | `dumpdir_locate` | `0x417fad` | x86-64 | O0 | 100 |
| 123 | `61d47a0eba77af02425667ab` | cleanflight | `dashboardUpdate` | `0x802c19c` | thumb | O0 | 292 |
| 124 | `3166901644d1c52fa49d5a0e` | e2fsprogs | `rebuild_extent_tree` | `0x4452d4` | x86-64 | O0 | 403 |
| 125 | `c55b8e98182753c875552361` | libexpat | `endDoctypeDecl` | `0x4025cb` | x86-64 | O0 | 925 |
| 126 | `a28a102ff27336a4e2b92783` | libopencm3 | `usart_wait_send_ready` | `0x80008b0` | thumb | O2 | 8 |
| 127 | `4dd90b524503d828f13d7eec` | tar | `print_stats` | `0x404f19` | x86-64 | O0 | 440 |
| 128 | `dea2411356e43dfc7c11bf04` | cleanflight | `cliDma` | `0x801e7c0` | thumb | O2 | 8 |
| 129 | `3b4c1caedf8528083d8dc7ff` | e2fsprogs | `ext2fs_inode_has_valid_blocks` | `0x465660` | x86-64 | O2-noinline | 10 |
| 130 | `7189920445acbfb77617ad9c` | libexpat | `nopEndElement` | `0x4026d0` | x86-64 | O2 | 1 |
| 131 | `ad3382a62786b028718b7e44` | libopencm3 | `console_puts` | `0x80001e4` | thumb | O2 | 56 |
| 132 | `614e59d287df1bda39343da4` | tar | `hash_directory_meta` | `0x414670` | x86-64 | O2 | 17 |
| 133 | `b36bfeeb3a9919a5742e1126` | cleanflight | `runcamDeviceClose5KeyOSDCableConnection` | `0x802cfd0` | thumb | O2 | 42 |
| 134 | `9bbd1398a96e20491b0ba39f` | e2fsprogs | `dict_set_allocator` | `0x43c930` | x86-64 | O2-noinline | 37 |
| 135 | `2be76979e2d1dca16e7a70ec` | libexpat | `markup` | `0x402c70` | x86-64 | O2 | 57 |
| 136 | `d3c1e4a4d65e86d90064ae03` | libopencm3 | `gpio_mode_setup` | `0x800058c` | thumb | O2 | 74 |
| 137 | `a666d1d30b4b410fdfedac10` | tar | `xheader_forbid_global` | `0x413b10` | x86-64 | O2 | 67 |
| 138 | `a8c65a98d64f7901c860238f` | cleanflight | `gyroInitFilterBiquadRCFIR2` | `0x8024880` | thumb | O2 | 112 |
| 139 | `8d392b7d486c82034f43f086` | e2fsprogs | `mark_bmap_range` | `0x435960` | x86-64 | O2-noinline | 96 |

</details>

### 文本 JSON 基线实验的 40 个训练函数

按当步冻结日志的顺序列出项目、原函数名及优化级别。每行四题，每题生成四次。步数链接给出模型实际看到的匿名地址和题面，可用 task_id 连接私有清单。预检和固定验证不计入下表。

| Step | 任务 1 | 任务 2 | 任务 3 | 任务 4 |
|---:|---|---|---|---|
| 1（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_1.jsonl`） | shadow · `is_owner` · O0 | sysvinit · `donologin` · O2 | dash · `savestr` · O2 | dash · `pushredir` · O2 |
| 2（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_2.jsonl`） | findutils · `usage` · O0 | diffutils · `xmmalloca` · O0 | coreutils · `base32_encode` · O2 | dash · `command` · O0 |
| 3（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_3.jsonl`） | kmod · `mod_free` · O2 | base-passwd · `process_old_entries` · O2 | grep · `treefails` · O2 | kmod · `cfg_files_insert_sorted` · O2 |
| 4（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_4.jsonl`） | coreutils · `any_live_files` · O0 | shadow · `catch_signals` · O2 | openssh-portable · `sshpkt_disconnect` · O2 | cronie · `free_entry` · O2 |
| 5（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_5.jsonl`） | gzip · `abort_gzip` · O2 | kmod · `index_write` · O0 | coreutils · `xalloc` · O0 | diffutils · `prepare_text` · O0 |
| 6（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_6.jsonl`） | freertos · `vPortSetupTimerInterrupt` · O2 | grep · `acexec_trans` · O0 | findutils · `traverse_tree` · O0 | cronie · `set_element` · O0 |
| 7（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_7.jsonl`） | diffutils · `mmalloca` · O2 | base-passwd · `unlock_files` · O0 | coreutils · `xcharalloc` · O2 | coreutils · `ximemdup0` · O2 |
| 8（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_8.jsonl`） | cronie · `load_database` · O0 | shadow · `resolve_hostname` · O0 | gzip · `gettime` · O0 | dash · `evaltree` · O2 |
| 9（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_9.jsonl`） | kmod · `rmmod_all` · O0 | bash · `mkseq` · O0 | bash · `sh_ttyerror` · O2 | sysvinit · `console_open` · O0 |
| 10（本地 `results/qwen35-supervised-3807371/attempt-6/rollouts/task_10.jsonl`） | kmod · `cfg_file_free` · O0 | sysvinit · `hdflush` · O2 | grep · `compare` · O2 | bash · `rl_vi_redo` · O2 |

补充统计：[训练时编译报错的长度分布](../results/setup/heuristic-3815284-metrics/compiler-diagnostics.zh.md)。文中标注“本地”的路径用于在实验工作区定位原始材料。
