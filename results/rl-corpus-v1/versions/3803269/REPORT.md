# RL corpus 构建与验收状态

- 范围：33 个训练/验证来源项目，98 个声明的构建组合。
- 构建状态：`{'ready': 62, 'failed': 36}`。
- 静态合格任务：57116。
- 真实工具审计：`{'ready': 1734, 'blocked': 59}`。
- 正式数据校验通过：True。
- 模型训练：未运行。奖励为 byte_match 代理分数。
- 历史 24 函数清单：尚未恢复；bzip2/ChibiOS 保持项目级隔离。

失败与未审计任务未计入正式数据；详情见 status.json、compile_report.json 和每次 build.log。
