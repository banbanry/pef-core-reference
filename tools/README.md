# PEF Tools · 确定性编程工具集

> © 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License
> 理论 → 工具闭环：本目录工具全部从 PEF 理论文档实现，确定性执行（stdlib only），每个工具均通过 CLE 探针自举审计（P0=0, P1=0）与正反样本测试。

## 目录

| 工具 | 理论来源 | 功能 | 验证 |
|---|---|---|---|
| `pef_prompt_optimizer.py` | 开放案提示词工程系统 | 提示词锚定优化：场景判定(终端/本地/在线)、锚点密度诊断、结构化输出检查、超参推荐、降级方案 | 强锚点样本 PASS(81/千字)、弱样本 FAIL(0) |
| `pef_state_ledger.py` | 弘信物流表单处理器 | 状态登记簿：π锚绑定、只追加账本、哈希链校验、特征向量数值化 | 篡改 QTY→999999 检出链断裂；向量归一化正确 |
| `pef_time_audit.py` | PEF 时间理论附录 | 时序审计：时序铁则、双轴一致性、时钟源标注、迟滞死区抖动检测 | 合规 PASS、倒置检出、抖动 5 次穿越检出 |
| `pef_operator_library.py` | PEF算子库完整细分+扩展版 | 算子库引擎：1480 条算子(680+800)构建/检索/域分类/π-Mod3 相位/场景匹配 | build 1480 条、检索命中、相位映射正确 |

## 快速开始

```bash
# 提示词锚定优化（强逻辑密度诊断）
python tools/pef_prompt_optimizer.py sample_prompt_strong.txt --verbose

# 状态登记簿（π锚 + 哈希链）
python tools/pef_state_ledger.py init --db ledger.json
python tools/pef_state_ledger.py add SINO=ABC123 QTY=100 --db ledger.json --source AWB.csv
python tools/pef_state_ledger.py verify --db ledger.json

# 时序审计（双轴 + 迟滞死区）
python tools/pef_time_audit.py verify events_ok.csv
python tools/pef_time_audit.py chattering signals2.csv

# 算子库检索（1480 条）
python tools/pef_operator_library.py search 差分进化
python tools/pef_operator_library.py list --domain F
```

## 设计原则

- **确定性**：无随机、无网络依赖，相同输入必得相同输出
- **可验证**：每个工具配套正/反样本，退出码可验收（0=PASS）
- **π锚可追溯**：state-ledger 每条记录绑定 π 锚坐标，链式哈希防篡改
- **诚实边界**：CIC 硬件参数（涉专利）不进入本公开仓库

## 指纹水印

所有工具文件头含指纹水印（© 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License），来源可追溯至 GitHub: https://github.com/banbanry
