# PEF Core Reference — AI 编程三剑客整合实现

> **Source**: https://github.com/banbanry/pef-core-reference
> **Author**: banbanry (沈鹭)
> **License**: MIT
> **PEF Architecture**: Anchored Determinism Meta-Architecture — 唯锚才有势差产生
> **Main theory repo**: [pef-architecture](https://github.com/banbanry/pef-architecture)

本仓库是 PEF 架构的**可运行生产内核**，整合了「AI 编程三剑客」的完整实现——从理论到代码，从幻觉检测到缺陷审计到信任锚定，三位一体质量体系。

---

## 🗡️ AI 编程三剑客总览

三剑客不是三个独立工具，而是**同一套 PEF 架构在三个正交维度上的部署**——解决 AI 代码质量的三个根本问题。

| 剑客 | 代号 | 核心价值 | 解决问题 | 目录 | 检测维度 |
|------|------|---------|---------|------|---------|
| **幻觉检测仪** | CIC | 识别 AI 生成的「空壳代码」 | **内容问题**——代码有没有实际内容 | `cic/` | 空函数/幽灵变量/假逻辑/TODO占位/复制粘贴/方言偏差 |
| **体检扫描仪** | CLE | 基于 1000 条故障库精准检测缺陷 | **质量问题**——代码有没有具体 Bug | `core/` | 缓冲区溢出/内存泄漏/除零/资源泄漏/污点传播/整数溢出 |
| **防伪身份证** | PEF-π | 给代码发不可篡改的身份证 | **信任问题**——代码是谁写的、有没有被篡改 | `pef_core/` + `tools/` | π锚定/哈希链/影子图/状态账本/时序审计/算子库 |

### 为什么需要三剑客？

单一工具只能解决一个维度的问题：

```
只有 CLE（体检扫描仪）：
  → 能检测出缓冲区溢出，但检测不出"这个函数是空的，AI根本没实现"

只有 CIC（幻觉检测仪）：
  → 能检测出空函数和幽灵变量，但检测不出"这个实现有缓冲区溢出"

只有 PEF-π（防伪身份证）：
  → 能证明代码没被篡改，但检测不出代码本身有没有问题

三剑客整合：
  → 先过滤幻觉（CIC）→ 再检测缺陷（CLE）→ 最后锚定信任（PEF-π）
  → 内容、质量、信任，三个维度全覆盖
```

---

## 🗡️ 剑客一：CIC 幻觉检测仪（`cic/`）

> AI 编程三剑客之三：解决「内容」问题——代码是不是 AI 敷衍生成的空壳

### 核心能力

| 检测类型 | 严重级别 | 检测项 |
|---------|---------|--------|
| **AI幻觉检测** | P0-P2 | 空函数体、幽灵变量、TODO占位、假逻辑/恒真条件、复制粘贴重复、注释密度异常 |
| **跨模型方言偏差** | P1-P2 | 架构分割指纹（大函数vs极小函数vs DTO泛滥）、错误处理指纹（裸try-catch vs Result包装）、状态副作用指纹、命名风格指纹 |
| **π实体锚定** | 结构级 | 每个代码实体（函数/类/接口）分配唯一πₛ锚号 |
| **LOCKED引用检查** | 结构级 | 只有通过完整审计的实体才能被引用 |
| **StateLedger哈希链** | 结构级 | 审计事件只追加禁删除，哈希链完整性验证 |

### 模型方言指纹库

基于训练数据特征推断的三大模型方言：

| 模型 | 架构风格 | 异常处理 | 状态副作用 | 命名风格 |
|------|---------|---------|-----------|---------|
| **DeepSeek** | 大函数/少文件/高内聚 | 裸try-catch吞异常 | 倾向修改入参 | 简洁/少注释 |
| **GLM** | 超薄控制器/极小函数 | 自定义异常枚举 | 倾向只读 | 详细/多注释 |
| **Trae** | DTO/适配器/helper泛滥 | Result<T>包装 | 倾向新建副本 | 冗长/过度抽象 |

### 使用方式

```bash
# AI幻觉检测
python cic/scripts/cic_cli.py hallucination --input <代码文件或目录>

# 跨模型方言偏差检测
python cic/scripts/cic_cli.py dialect --input <代码文件或目录> --model-source auto

# 完整审计（幻觉+方言+π锚定+LOCKED）
python cic/scripts/cic_cli.py audit --input <代码文件或目录> --out-dir <结果目录>

# π实体锚定
python cic/scripts/cic_cli.py anchor --input <代码文件或目录>
```

### 参考文档

- `cic/references/model-dialect-fingerprints.md` — AI代码方言指纹库（四大维度+D-S调度λ）
- `cic/references/probe-checklist.md` — 14+6探针清单（结构级/语义级/行为级三层）

---

## 🗡️ 剑客二：CLE 体检扫描仪（`core/`）

> AI 编程三剑客之二：解决「质量」问题——代码有没有具体 Bug 和安全漏洞

### 核心能力

| 模块 | 功能 | 关键算子 |
|------|------|---------|
| **物理不变量算子** | 4大物理不变量检测 | 时间单调性、资源界限、状态有界性、确定性求解 |
| **PEF扩展算子** | 14个E层算子（V3.9.2） | 缓冲区溢出、未初始化内存、资源泄漏、整数溢出、路径覆盖、数据竞争、危险函数、malloc NULL检查 |
| **跨函数污点传播** | BFS+别名+SANITIZER三级阻断 | scanf→step2→sink→system 三级链实测检出 |
| **D-S证据融合** | Dempster/Yager融合+四证据源 | P0硬阻断→FAIL，高冲突K=0.81→Yager |
| **L1-L3流水线** | 确定性探针+AI交叉比对+金丝雀注入 | Layer3防"假审计"，C1-C4金丝雀真实执行 |
| **拜占庭对抗测试** | 11个真实对抗场景 | S5=0.0，healthy=True |

### V3.9.2 新增算子

| 算子ID | 算子名称 | 检测能力 | 严重级别 |
|--------|---------|---------|---------|
| E057 | DangerousFunctionDetector | gets/vsprintf/scanf(%s)/getwd/crypt 危险函数 | P0-P2 |
| E058 | MallocNullCheckDetector | malloc/calloc/realloc 返回值 NULL 检查追踪（5行窗口上下文） | P0 |

**去重设计**：strcpy/sprintf/strcat 已由 BufferOverflowDetector(E039) 覆盖，不重复检测。

### 使用方式

```bash
# 单文件审计（Layer 1 确定性探针 + PEF扩展）
python core/cle_deploy.py audit source.c

# 双层审计（Layer 1 + Layer 2 AI交叉比对）
python core/cle_deploy.py dual source.c

# 拜占庭对抗测试（11个场景）
python core/cle_deploy.py byzantine

# 脏数据注入验收（Layer 3 防假测试）
python core/cle_deploy.py inject source.c

# 模块完整性验证
python core/cle_deploy.py verify
```

### 验证结果

- **回归测试**：49/49 PASS
- **拜占庭测试**：11/11 PASS（S5=0.0）
- **特征库**：720条，哈希完整性 OK
- **真实扫描**：~1100行 C++17 代码库检出 95 项（P0=4, P1=91）
- **V3.9.2 新算子验证**：gets命中P0，malloc NULL检查命中P0，clean code不误报

---

## 🗡️ 剑客三：PEF-π 防伪身份证（`pef_core/` + `tools/`）

> AI 编程三剑客之一：解决「信任」问题——代码是谁写的、有没有被篡改、逻辑链是否完整

### 核心能力

| 模块 | 功能 | 目录 |
|------|------|------|
| **π锚定核心** | 不可伪造的π锚坐标、MOD3域调度、防向量坍缩 | `pef_core/pi_constants.py`, `pef_core/pi_tools.py` |
| **状态账本** | 只追加禁删除的哈希链账本、SHA-256裁决印章 | `pef_core/state_ledger.py`（29KB） |
| **影子图协议** | 层间逻辑链完整性保障、接口签名校验 | `pef_core/pef_shadow_graph.py` |
| **信息熵计算** | 熵代价机制、密度封顶+结构校验双闸门 | `pef_core/information_entropy.py` |
| **证据理论** | D-S证据融合、Dempster/Yager组合规则 | `pef_core/evidence_theory.py` |
| **算子组合** | PEF算子组合调度、π-Mod3相位驱动 | `pef_core/operator_combination.py` |
| **自检清单** | PEF自检8项、P0熔断、账本留痕 | `pef_core/pef_self_checklist.py` |
| **软件状态向量** | S1-S7七维状态向量真实计算 | `pef_core/software_state_vector.py` |

### 工具集（`tools/`）

| 工具 | 功能 |
|------|------|
| `pef_prompt_optimizer.py` | PEF提示词优化器 |
| `pef_state_ledger.py` | PEF状态账本工具 |
| `pef_time_audit.py` | PEF时序审计工具 |
| `pef_operator_library.py` | PEF算子库工具（262KB算子数据） |

### π锚定的真实定位

> **π 不是密码学安全原语，而是防止大模型内部向量压缩/截断/四舍五入把 π 坍缩成 3.14 短近似值；强制系统取用 π 无限展开的高位小数片段获得持续变化坐标序列。**

- π 的价值不在信息量，而在**不可伪性**和**防向量坍缩**
- 系统安全性来源于哈希链、M层权限隔离、日志审计，而非π常数本身
- π可以替换为其他长数字序列，架构主体不受破坏

---

## 🔗 三剑客协作流程

```
┌─────────────────────────────────────────────────────────────┐
│                    AI 生成代码                                │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  🗡️ CIC 幻觉检测仪（cic/）                                   │
│  ─────────────────────────────────────────────────────────  │
│  • 空函数体检测（P0）                                        │
│  • 幽灵变量检测（P0）                                        │
│  • 假逻辑/恒真条件检测（P1）                                 │
│  • TODO占位符检测（P1）                                      │
│  • 复制粘贴重复检测（P2）                                    │
│  • 跨模型方言偏差检测（P1-P2）                               │
│  ─────────────────────────────────────────────────────────  │
│  裁决：P0>0 → 阻断退回（空壳代码不进入下一环节）             │
└──────────────────────────────┬──────────────────────────────┘
                               │ 通过幻觉检测
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  🗡️ CLE 体检扫描仪（core/）                                  │
│  ─────────────────────────────────────────────────────────  │
│  • 4大物理不变量算子                                         │
│  • 14个PEF扩展算子（V3.9.2新增gets/malloc NULL检查）        │
│  • 跨函数污点传播（BFS+别名+SANITIZER）                     │
│  • D-S证据融合（Dempster/Yager）                             │
│  • L1-L3流水线（确定性探针+AI交叉比对+金丝雀注入）          │
│  • 11个拜占庭对抗场景                                        │
│  ─────────────────────────────────────────────────────────  │
│  裁决：P0>0 → 阻断退回（有缺陷的代码不进入下一环节）         │
└──────────────────────────────┬──────────────────────────────┘
                               │ 通过缺陷检测
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  🗡️ PEF-π 防伪身份证（pef_core/ + tools/）                  │
│  ─────────────────────────────────────────────────────────  │
│  • π实体锚定（每个代码实体分配唯一πₛ锚号）                   │
│  • StateLedger哈希链账本（只追加禁删除）                     │
│  • 影子图协议（层间逻辑链完整性）                             │
│  • SHA-256裁决印章                                           │
│  • LOCKED引用检查（只有通过审计的实体才能被引用）             │
│  ─────────────────────────────────────────────────────────  │
│  结果：代码获得不可篡改的身份证，全链路可追溯                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    ✅ 交付（内容+质量+信任全覆盖）            │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始（30秒）

```bash
git clone https://github.com/banbanry/pef-core-reference.git
cd pef-core-reference
pip install -r requirements.txt

# 运行最小演示（8项自检，含P0熔断和篡改检测）
python demo_minimal.py
```

**预期输出（最后一行）：**
```
SELF-CHECK: 8/8 PASS
Ledger: 4 entries, tail=xxxx...
```

退出码 `0` = PASS。这是机器可提取的验收信号。

### 三剑客分别测试

```bash
# 🗡️ CIC 幻觉检测
python cic/scripts/cic_cli.py audit --input core/ --out-dir cic_output

# 🗡️ CLE 缺陷检测
python core/cle_deploy.py audit core/cle_deploy.py

# 🗡️ CLE 拜占庭测试
python core/cle_deploy.py byzantine

# 🗡️ PEF-π 最小演示（含π锚定+哈希链+篡改检测）
python demo_minimal.py
```

---

## 📊 验证结果汇总

| 剑客 | 测试项 | 结果 |
|------|--------|------|
| **CIC** | AI幻觉检测（测试样本） | 23条发现（P0=17, P1=3, P2=3），π锚定29个实体 |
| **CIC** | 哈希链完整性 | ✅ 完整 |
| **CLE** | 回归测试 | 49/49 PASS |
| **CLE** | 拜占庭对抗测试 | 11/11 PASS（S5=0.0） |
| **CLE** | 特征库 | 720条，哈希完整性 OK |
| **CLE** | V3.9.2新算子 | gets命中P0，malloc NULL检查命中P0，clean code不误报 |
| **CLE** | 真实扫描 | ~1100行 C++17 检出95项（P0=4, P1=91） |
| **PEF-π** | 最小演示自检 | 8/8 PASS |
| **PEF-π** | P0熔断 | ✅ 未锚定写入触发熔断 |
| **PEF-π** | 篡改检测 | ✅ 洋葱哈希不匹配检出 |

---

## 📁 仓库结构

```
pef-core-reference/
├── README.md                    # 本文件（三剑客区分介绍）
├── demo_minimal.py              # 最小演示（8/8自检，P0熔断+篡改检测）
├── requirements.txt             # 依赖
├── CONTRIBUTING.md              # 贡献指南
│
├── cic/                         # 🗡️ 剑客一：CIC 幻觉检测仪
│   ├── scripts/
│   │   └── cic_cli.py          # 核心检测引擎（AI幻觉+方言偏差+π锚定）
│   └── references/
│       ├── model-dialect-fingerprints.md  # AI代码方言指纹库
│       └── probe-checklist.md              # 14+6探针清单
│
├── core/                        # 🗡️ 剑客二：CLE 体检扫描仪
│   ├── cle_deploy.py            # 部署入口（audit/dual/byzantine/inject/verify）
│   ├── cle_base_layer.py        # 公底层定义（九大定义）
│   ├── cle_probe_engine.py      # 探针引擎（Gate0-8）
│   ├── pef_operators.py         # PEF扩展算子（14个，V3.9.2）
│   ├── python_operators.py      # Python特有算子（14个）
│   ├── taint_propagation.py     # 跨函数污点传播（BFS+别名）
│   ├── ds_evidence_fusion.py    # D-S证据融合
│   ├── byzantine_tests.py       # 拜占庭对抗测试（11场景）
│   ├── layer2_ai_review.py      # L2 AI交叉比对
│   ├── layer3_injection_verifier.py  # L3 金丝雀注入验收
│   ├── secure_pi_provider.py    # π调度（SecurePiDigitProvider）
│   ├── onion_pipeline.py        # 洋葱流水线三级阻断
│   ├── cle_v38_engine.py        # V3.8主引擎统一入口
│   ├── signature_library.py     # 特征库注册表
│   ├── signature_library_data.py # 720条特征库数据
│   ├── scene_adapter.py         # 场景适配器
│   ├── sharded_pi_coordinator.py # 分片π协调器
│   ├── base_operator.py         # 算子基类+工厂
│   ├── audit_log_chain.py       # 审计日志链
│   └── fault_library_1000.json  # 1000条PEF/MOD故障库
│
├── pef_core/                    # 🗡️ 剑客三：PEF-π 防伪身份证
│   ├── state_ledger.py          # 状态账本（29KB，哈希链只追加）
│   ├── pi_constants.py          # π常数（防向量坍缩）
│   ├── pi_tools.py              # π工具
│   ├── pef_shadow_graph.py      # 影子图协议
│   ├── information_entropy.py   # 信息熵计算
│   ├── evidence_theory.py       # 证据理论
│   ├── operator_combination.py  # 算子组合调度
│   ├── pef_self_checklist.py    # PEF自检清单
│   ├── software_state_vector.py # 软件状态向量S1-S7
│   ├── abstract_auditor.py      # 抽象审计器
│   ├── config_loader.py         # 配置加载器
│   ├── semantic_error.py        # 语义错误
│   ├── pefmod.py                # PEF模块
│   ├── utils.py                 # 工具函数
│   └── __init__.py              # 包初始化
│
├── tools/                       # PEF工具集
│   ├── pef_prompt_optimizer.py # 提示词优化器
│   ├── pef_state_ledger.py      # 状态账本工具
│   ├── pef_time_audit.py        # 时序审计工具
│   ├── pef_operator_library.py  # 算子库工具
│   ├── operator_library.json    # 算子库数据（262KB）
│   └── README.md                # 工具说明
│
├── evaluation/                  # A/B测试评估
│   ├── run_ab_test.py           # A/B测试运行器
│   ├── lib/                     # 测试库（裸提取器vs PEF增强提取器）
│   ├── data/                    # 测试数据
│   └── output/                  # 测试输出（A/B报告）
│
├── config/                      # 配置
│   └── framework_config.json    # 框架配置
│
└── .github/                     # GitHub配置
    ├── workflows/ci.yml         # CI/CD流水线
    └── ISSUE_TEMPLATE/          # Issue模板
```

---

## 🔗 与理论仓库的关系

```
pef-architecture（理论 + 证据）
├─ 01-core-spec              设计规范（三元原语、公理、MOD3、五层流水线）
├─ 02-applications           CIC / PIMEM / π-anchor 应用理论
├─ 03-operator-library       800+ 算子分类体系
├─ 04-engineering-cases      CLE 部署案例、95项发现报告
├─ 05-references             外部参考
└─ review/                    外部评审回应
        │
        ▼ 理论落地
pef-core-reference（本仓库 — 三剑客可运行实现）
├─ cic/                       CIC 幻觉检测仪实现
├─ core/                      CLE 体检扫描仪实现
├─ pef_core/ + tools/        PEF-π 防伪身份证实现
├─ demo_minimal.py            最小演示（8/8自检）
└─ evaluation/                A/B测试评估
```

---

## 🔒 完整性与个人指纹

- 每个模块都携带 PEF 头部水印（`Anchored Determinism Meta-Architecture`）
- 来源归属：https://github.com/banbanry/pef-architecture（MIT）
- 脱敏处理：无客户名称、无业务数据、无专利/原理图细节
- 硬件部分涉专利已从公开仓库移除
- 如分叉或复用，请保留头部水印和来源归属

---

## 📄 License

MIT © 2026 banbanry (沈鹭). See LICENSE in the main repository.

---

> **三剑客一句话总结**：若要根治软件腐化，选 PEF-π；若要提防 AI 幻觉，选 CIC；若要精准捉虫，选 CLE。理想的状态是三位一体——内容、质量、信任，三个维度全覆盖。
