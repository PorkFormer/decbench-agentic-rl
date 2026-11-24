# A-v2 输出质量、byte_match 奖励与可读性审查

本次审查读取已保存的 32 个固定验证任务在 step 0/1/2/5 的最终 C、工具事件、评分元数据与私有快照分数，并参考相应项目源码。没有重新生成、执行目标程序或重评分，没有修改正在运行的实验。step 10 当时尚未完整，不纳入本报告。

## 结论

1. A-v2 的终局任务奖励直接等于 `ByteMatchMetric` 的结果。不是 learned reward model，也不是多个能力指标的综合分数。没有结构体恢复、命名、可读性或原始可编译性奖励；actor 的 KL 正则是另外的优化约束。
2. 发现真实的结构体写法退回数组/指针写法，以及 raw compile 退步而代理奖励上升的实例。没有发现可证明“正确结构体改成指针偏移因此拿到更高奖励”的配对实例；现有证据不足以把总体改善归因于这种策略。
3. 平均奖励从 0.27692647 到 0.44042813 的提升，主要来自原来零分/评分器编译失败的样例变为可评分。原来已有正分的 15 个任务，合计分数反而小幅下降。
4. 高 byte_match 不能作为可读性、类型恢复或语义正确性提升的证据。当前实验只能报告它实际优化的代理指标及独立的格式/编译指标。

## 奖励路径

`decbench/rl/worker.py:185` 读取最终文件，做 `_sanitize` 和目标函数重命名，调用 `ByteMatchMetric.compute_for_function`，将 `metric.value` 作为 `score`。
`heuristic_env.py:136` 返回终局分数；`heuristic.action_advantages` 中 A 组对所有动作使用终局 GRPO 优势 G。私有中间 Q/C 在 A 组只记录，不加入优势，也不展示给模型。

byte_match 会先进行确定性编译修复，再比较机器码；若字节不完全一致，则主要比较归一化汇编行的 Jaccard 类相似度。直接调用/跳转目标、部分 PC/RIP 相对操作数被归一化，因此 1.0 不一定等于机器码逐字节一致，更不证明外部函数/全局变量身份正确。原始源码中的类型/字段可读性不参与这个分数。

## 定量分解（step 0 → step 5）

| 观察 | 训练前 | Step 5 |
|---|---:|---:|
| 平均 byte_match | 0.27692647 | 0.44042813 |
| 评分器判定可编译 | 15/32 | 23/32 |
| 原始代码编译检查通过 | 11/32 | 16/32 |
| 有输出文件 | 24/32 | 30/32 |
| 正奖励但原始代码编译检查不通过 | 4/32 | 7/32 |
| 含 struct / `->` 的输出（词法筛查） | 1/32 | 0/32 |
| 含类型转换后解引用的输出（词法筛查） | 9/32 | 12/32 |

原来零分的 17 个任务中，9 个变成正分：对整体验证均值贡献 **+0.17413530**。
原来正分的 15 个任务：对均值净贡献 **−0.01063364**。
相加得到总变化 **+0.16350166**。这不是干预式因果分解，只是相同任务的分数组成核算。
词法筛查不是可靠的可读性评分；例如硬件 MMIO 本来就需要地址访问，结构体存在也不代表定义正确。

## 人工核查的具体样例

### 1. dict_set_allocator：确实丢失结构体表达，但没有获得更高奖励

源码 `lib/support/dict.c` 使用 `dict->allocnode`、`dict->freenode`、`dict->context`。
step 0 模型生成 `struct dict_allocator`（字段只是 `field_0...field_11`，定义并未验证正确），并使用：

```c
a1->field_11 = a4;
a1->field_9 = a2;
a1->field_10 = a3;
```

step 5 删除结构体，改成 `_QWORD *a1`：

```c
a1[11] = a4;
a1[9] = a2;
a1[10] = a3;
```

奖励 **0 → 0**，原始编译均失败。这支持“结构化表达退化确实出现”，不支持“这次改写因为奖励更高而被选中”的因果结论。step 1/2 仍有结构体，step 5 才消失。
证据：diff（本地 `results/setup/heuristic-3815284-output-audit/cases/9bbd1398a96e20491b0ba39f/step0-to-step5.diff`），源码上下文（本地 `results/setup/heuristic-3815284-output-audit/dict-source.txt`）。

### 2. ext2fs_blocks_count：奖励提高，但没有恢复原结构体

原源码：

```c
return super->s_blocks_count |
    (ext2fs_has_feature_64bit(super) ?
     (__u64)super->s_blocks_count_hi << 32 : 0);
```

step 0 无输出。step 5 的主体是：

```c
v1 = *(unsigned int *)(a1 + 4);
if ((unsigned int)sub_452EDD(a1))
    v2 = (unsigned long long)*(unsigned int *)(a1 + 336) << 32;
```

奖励 **0 → 0.25**，原始编译通过。改善是从无输出到可评分产物；这是低层次恢复，不能说结构体恢复改善，也不是观察到“训练前好结构体被破坏”。
证据：step 5 C（本地 `results/setup/heuristic-3815284-output-audit/cases/0609ac295ee74ec00fdff28c/step5.c`），源码（本地 `results/setup/heuristic-3815284-output-audit/blocks-source.txt`）。

### 3. sys_compare_gid：涨分主要来自编译修复，字段语义依旧丢失

源码为 `a->st_gid == b->st_gid`。前后输出都使用偏移 `+32`，step 5 将缺失的 `DWORD` 换成 `unsigned int` 并补上类型依赖，奖励 **0 → 0.625**，原始编译 **0 → 1**。没有恢复 `struct stat` 或字段名。
证据：diff（本地 `results/setup/heuristic-3815284-output-audit/cases/c06bc0da0da620b18b7e81c2/step0-to-step5.diff`），源码（本地 `results/setup/heuristic-3815284-output-audit/gid-source.txt`）。

### 4. gyroInitFilterBiquadRCFIR2：奖励提高，但独立编译退步

step 0 生成完整声明与类型别名，原始编译通过，奖励 **0.13235294**；step 5 直接使用 IDA 伪代码样式，保留 `__fastcall`、`_DWORD`、`*(... + 2028)`、`36*i + 2032`，删除原声明，原始编译失败，评分器仍给 **0.35**（fixup 2 轮、注入 5 项）。step 5 代码去掉首尾空白后与该轮 IDA 观察一致。

但不能只判为无意义取巧：step 0 把 `nullsub_14` / `sub_800C876` 写成了函数调用，step 5 改回地址赋值；源码确实在设置函数指针。这可能包含合理行为修正。已确认的是“奖励改善与产物独立可编译性脱钩”，不是已证明恶意利用评分器。
证据：diff（本地 `results/setup/heuristic-3815284-output-audit/cases/a8c65a98d64f7901c860238f/step0-to-step5.diff`），IDA（本地 `results/setup/heuristic-3815284-output-audit/cases/a8c65a98d64f7901c860238f/step5-ida-observation.txt`），源码（本地 `results/setup/heuristic-3815284-output-audit/gyro-source.txt`）。

### 5. unknownEncodingConvert：满分不代表原始代码可用或字节完全一致

step 0 有重复函数定义、递归样式错误包装，分数 0。step 5 删除这些错误，保留一个简短 wrapper，得到 **1.0**，但 `__fastcall` 等仍导致原始代码编译失败。评分器 fixup 2 轮、注入 1 项。
元数据明确是 `exact_match=false`、`jaccard_similarity=1.0`，原始函数 38 字节、重编译 43 字节。它是归一化汇编匹配满分，不能描述为精确字节匹配或语义验收通过。
证据：diff（本地 `results/setup/heuristic-3815284-output-audit/cases/b661a0955b55e9b577e30d9d/step0-to-step5.diff`），`comparison.json` 中 metadata，源码（本地 `results/setup/heuristic-3815284-output-audit/encoding-source.txt`）。

### 6. name_term：硬编码地址换取可编译产物，存在明显语义风险

源码为 `free(name_buffer)`；IDA 为 `sub_452D4C(qword_68FCD8)`。
step 5 最终输出却变成：

```c
return sub_452D4C((int64_t)0x68FCD8);
```

读取全局变量保存的指针与直接传全局地址不是同一件事。这是实质性的语义风险，不只是可读性下降。最终评分 **0 → 0.625**，原始编译从失败变成功；尚未执行独立语义验证。

同一 step 5 轨迹的私有快照还显示：改成硬编码地址前 **Q=1.0、C=0**，地址替换后 **Q=0.625、C=0**，修复类型后 **Q=0.625、C=1**。因此地址替换本身并没有提高该轨迹的 byte_match，反而降低了它。模型看见的是编译错误，未看见这些私有 Q/C，不能据此声称它有意识地搜索评分漏洞。
证据：diff（本地 `results/setup/heuristic-3815284-output-audit/cases/413480b27f20b07a1b9657f1/step0-to-step5.diff`），源码（本地 `results/setup/heuristic-3815284-output-audit/name-term-source.txt`），原始 episode 的 score/actions 与 events。

### 7. nopProcessingInstruction：出现内联汇编输出，但未获奖励

step 5 将 IDA 风格的 `push rbp`、`mov [rbp+var_8], rdi`、`retn` 拼入 `__asm__ volatile`。评分与原始编译均为 0，不能描述为成功的奖励攻击。
证据：step 5 C（本地 `results/setup/heuristic-3815284-output-audit/cases/b50decd00dfb54a133a38a74/step5.c`）。

## 后续建议（尚未修改实验）

- 将原始可编译率、类型/结构恢复、可读性与 byte_match 分开报告；将现有提升称为代理分数提升。
- 若训练目标是可维护 C，后续可设置原始编译门槛，并把诊断修复后的分数作为辅助指标；须冻结新奖励版本并重新评估基线，不修改现有 A 对照。
- 在确认源程序确实存在结构体的任务上，单独审计字段恢复与魔数偏移；不能一概惩罚指针算术，否则会误伤 MMIO、数组及合法底层代码。
- 原生工具调用能改善协议，但不会自动解决奖励目标与可读性的错位。增加过程奖励若仍只依赖 byte_match 和编译，仍然没有直接优化类型/可读性。
- 行为正确性需要独立测试/语义验证。当前没有用运行测试验证上述输出。

## 产物与限制

- `comparison.json`：全部 32 任务 × 4 阶段的分数、编译结果、元数据和词法线索。
- `cases/<task>/step*.c`、`step0-to-step5.diff`：完整实际输出与差异。
- `audit.json`：汇总、分数分解、原始证据 SHA256。
- 原始项目源码摘录用于人工理解；不等同于逐配置预处理后源码的语义证明。
- 没有通过编译不同等价写法的反事实实验验证“结构体改指针能提高分数”；该断言不能从 byte_match 定义直接推出。等价结构体和指针表达可能编译为相同指令。
