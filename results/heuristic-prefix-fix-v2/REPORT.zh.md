# A 组 v1 前缀失败与 v2 修复

3811391 / attempt-1 完成 16 个任务 × 4 条真实预检 rollout：38/64 可编译，
14/64 无输出，14/16 个任务有组内终局奖励差异。训练样本转换在严格 token
前缀检查失败；没有参数更新、checkpoint 或验证改善证据。

保存的原始 token 记录中有 8/64 条轨迹在 decode→encode 后序列变化。
v1 的后续生成通过文本聊天接口重新分词，训练则保留生成原始 token。
已生成 token 与重新编码文本不能保证前缀相同。

v2 将拼接后的原始 token IDs 直接传给 vLLM，服务端检查 engine 实际 prompt IDs
并回传，客户端再次检查。工具观察使用同一裁剪版本；仅真实生成 token 参与 loss。
每轮生成立即落盘，整条轨迹仍保留严格前缀、动作、mask 和长度检查。

独立副本：`.tools/AgentEvolver-heuristic-v2`、`.tools/verl-heuristic-v2`。
旧副本不改写；修改前的共享脚本、配置、测试和源码锁在本目录 `original/`。
奖励公式、四组对照、数据、seed、训练预算均不变。

验证在原 allocation 内完成：27 个测试通过；真实 Qwen3.5 两轮生成通过，
包括非规范输入 token、第二轮 5051-token 输入、5040-token response、精确前缀和 loss mask。
工具/评分代码哈希未变化，沿用 CPU 作业 3811380 的真实工具检查。
这些证明修复路径可运行，不等于四卡训练更新、16K backward 或效果验收。

旧作业提交时锁已固定，修复版必须使用新源码锁和有明确替代关系的 A 组提交；
不能在旧锁下盲目写 retry。B/C/D 仍等待新 A 组 GPU 训练门槛通过。

替代提交：3815284（A-v2），源码锁 SHA256 为
`f96436dc6e00834b4c16899f7978a843dbcdbb0ab1365b63ef976d8396cf78c6`。
旧作业 3811391 于 2026-11-03 11:38:40 被监督者取消以释放 allocation；
11:39 Asia/Shanghai 新作业为 PENDING / Priority，尚无新参数更新。
新 watcher 为 `heuristic-watch-3815284`，注册表为
`results/heuristic-submission-A-v2.json`。
