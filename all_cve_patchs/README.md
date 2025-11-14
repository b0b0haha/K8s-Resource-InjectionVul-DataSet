# Kubernetes CVE 补丁集合

本目录包含了一个全面的 Kubernetes 相关 CVE（通用漏洞披露）补丁和漏洞信息集合。该集合包含从 2016 年到 2025 年的 125 个 CVE 条目，包含详细的补丁文件、提交信息和漏洞元数据。

## 📁 目录结构

```
all_cve_patchs/
├── cve_report.md                    # 详细的 CVE 报告信息
├── README.md                        # 英文版说明文档
├── README_CN.md                     # 中文版说明文档（本文件）
└── patch_info/
    ├── cve_patch/                   # 包含补丁文件的各个 CVE 目录
    │   ├── CVE-2016-1905/          # CVE 目录结构示例
    │   │   ├── vulnerability_info.json
    │   │   ├── vulnerability_statistics.json
    │   │   ├── commit_info_1_e90c2bd7.json
    │   │   ├── commit_url_1_e90c2bd7.txt
    │   │   └── patch_1_e90c2bd7.patch
    │   ├── CVE-2017-1000056/
    │   ├── CVE-2017-1002101/
    │   └── ... (共 125 个 CVE 目录)
    ├── cve_folder_stats_20250725_050504.json    # CVE 文件夹统计信息
    ├── cve_patch-deduplicated-cleaned.json      # 去重和清理后的补丁数据
    └── cve_patch-cleaned-final.json             # 最终清理后的补丁数据
```

## 📊 集合统计

- **CVE 总数**: 125 个漏洞
- **时间范围**: 2016-2025
- **GitHub 仓库**: 涉及 147 个仓库
- **编程语言**: Go (139), TypeScript (3), Java (1), Rust (1), HTML (1), Python (1), Makefile (1)

## 📋 CVE 信息结构

每个 CVE 目录包含以下文件：

### 核心文件
- **`vulnerability_info.json`**: 基本 CVE 信息，包括描述、引用和相关 URL
- **`vulnerability_statistics.json`**: 漏洞的统计信息
- **`commit_info_*.json`**: 修复漏洞的每个提交的详细信息
- **`commit_url_*.txt`**: 仓库中提交的 URL
- **`patch_*.patch`**: 统一差异格式的实际补丁文件

### CVE 结构示例
```
CVE-2016-1905/
├── vulnerability_info.json          # CVE 元数据和引用
├── vulnerability_statistics.json    # 漏洞统计信息
├── commit_info_1_e90c2bd7.json     # 提交详情
├── commit_url_1_e90c2bd7.txt       # 提交 URL
└── patch_1_e90c2bd7.patch          # 实际补丁文件
```

## 🔍 主要特性

### 1. 全面覆盖
- 涵盖 2016 年至 2025 年的 Kubernetes 漏洞
- 包括核心 Kubernetes 和生态系统漏洞
- 包含各种严重级别的补丁

### 2. 详细元数据
- 漏洞描述和影响分析
- 安全公告和 GitHub 问题的引用
- 包含时间戳和作者的提交信息
- 拉取请求和问题跟踪

### 3. 补丁分析就绪
- 清洁、去重的补丁文件
- 用于自动化分析的结构化 JSON 元数据
- 保留提交 URL 以供验证和进一步调查

## 📈 数据文件

### `cve_report.md`
包含以下内容的综合报告：
- 每个 CVE 的详细描述
- 相关 GitHub 仓库及其元数据
- 拉取请求和提交信息
- 安全公告的引用链接

### `cve_patch-cleaned-final.json`
最终清理数据集，包含：
- 去重的补丁信息
- 结构化漏洞数据
- 可用于自动化分析

### `cve_patch-deduplicated-cleaned.json`
中间清理数据集，包含：
- 移除重复项
- 标准化格式
- 质量保证数据

## 🛠️ 使用方法

### 对于研究人员
1. 使用 `cve_report.md` 获取全面的漏洞概览
2. 访问各个 CVE 目录进行详细的补丁分析
3. 利用 JSON 文件进行自动化数据处理

### 对于安全分析
1. 审查补丁文件以了解漏洞修复
2. 分析提交模式和时机
3. 研究漏洞随时间的演变

### 对于开发团队
1. 参考类似漏洞的补丁
2. 了解安全最佳实践
3. 从历史安全问题中学习

## 🔗 相关资源

- **主报告**: `cve_report.md` - 完整的漏洞分析
- **统计信息**: `cve_folder_stats_20250725_050504.json` - 集合统计
- **清理数据**: `cve_patch-cleaned-final.json` - 可用于分析的数据集

## 📝 注意事项

- 所有补丁文件均为统一差异格式
- JSON 文件包含用于自动化处理的结构化元数据
- 保留提交 URL 以供验证和进一步调查
- 该集合会定期更新新的 CVE 发现

## 🤝 贡献

该集合是更大的 Kubernetes 安全研究项目的一部分。如有问题或贡献，请参考主项目文档。

---

*最后更新: 2025年7月*
*CVE 总数: 125*
*覆盖范围: 2016-2025* 