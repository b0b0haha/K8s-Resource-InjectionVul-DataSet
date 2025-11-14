# Kubernetes CVE Patches Collection

This directory contains a comprehensive collection of Kubernetes-related CVE (Common Vulnerabilities and Exposures) patches and vulnerability information. The collection includes 125 CVE entries spanning from 2016 to 2025, with detailed patch files, commit information, and vulnerability metadata.

## 📁 Directory Structure

```
all_cve_patchs/
├── cve_report.md                    # Comprehensive CVE report with detailed information
├── README.md                        # This file
└── patch_info/
    ├── cve_patch/                   # Individual CVE directories containing patch files
    │   ├── CVE-2016-1905/          # Example CVE directory structure
    │   │   ├── vulnerability_info.json
    │   │   ├── vulnerability_statistics.json
    │   │   ├── commit_info_1_e90c2bd7.json
    │   │   ├── commit_url_1_e90c2bd7.txt
    │   │   └── patch_1_e90c2bd7.patch
    │   ├── CVE-2017-1000056/
    │   ├── CVE-2017-1002101/
    │   └── ... (125 CVE directories total)
    ├── cve_folder_stats_20250725_050504.json    # Statistics about CVE folders
    ├── cve_patch-deduplicated-cleaned.json      # Deduplicated and cleaned patch data
    └── cve_patch-cleaned-final.json             # Final cleaned patch data
```

## 📊 Collection Statistics

- **Total CVE Count**: 125 vulnerabilities
- **Time Range**: 2016-2025
- **GitHub Repositories**: 147 repositories involved
- **Programming Languages**: Go (139), TypeScript (3), Java (1), Rust (1), HTML (1), Python (1), Makefile (1)

## 📋 CVE Information Structure

Each CVE directory contains the following files:

### Core Files
- **`vulnerability_info.json`**: Basic CVE information including description, references, and related URLs
- **`vulnerability_statistics.json`**: Statistical information about the vulnerability
- **`commit_info_*.json`**: Detailed information about each commit that fixes the vulnerability
- **`commit_url_*.txt`**: URLs to the commits in the repository
- **`patch_*.patch`**: The actual patch files in unified diff format

### Example CVE Structure
```
CVE-2016-1905/
├── vulnerability_info.json          # CVE metadata and references
├── vulnerability_statistics.json    # Vulnerability statistics
├── commit_info_1_e90c2bd7.json     # Commit details
├── commit_url_1_e90c2bd7.txt       # Commit URL
└── patch_1_e90c2bd7.patch          # Actual patch file
```

## 🔍 Key Features

### 1. Comprehensive Coverage
- Covers Kubernetes vulnerabilities from 2016 to 2025
- Includes both core Kubernetes and ecosystem vulnerabilities
- Contains patches for various severity levels

### 2. Detailed Metadata
- Vulnerability descriptions and impact analysis
- References to security advisories and GitHub issues
- Commit information with timestamps and authors
- Pull request and issue tracking

### 3. Patch Analysis Ready
- Clean, deduplicated patch files
- Structured JSON metadata for automated analysis
- Commit URLs for verification and further investigation

## 📈 Data Files

### `cve_report.md`
A comprehensive report containing:
- Detailed descriptions of each CVE
- Related GitHub repositories with metadata
- Pull request and commit information
- Reference links to security advisories

### `cve_patch-cleaned-final.json`
Final cleaned dataset containing:
- Deduplicated patch information
- Structured vulnerability data
- Ready for automated analysis

### `cve_patch-deduplicated-cleaned.json`
Intermediate cleaned dataset with:
- Removed duplicates
- Standardized format
- Quality-assured data

## 🛠️ Usage

### For Researchers
1. Use `cve_report.md` for comprehensive vulnerability overview
2. Access individual CVE directories for detailed patch analysis
3. Utilize JSON files for automated data processing

### For Security Analysis
1. Review patch files to understand vulnerability fixes
2. Analyze commit patterns and timing
3. Study vulnerability evolution over time

### For Development Teams
1. Reference patches for similar vulnerabilities
2. Understand security best practices
3. Learn from historical security issues

## 🔗 Related Resources

- **Main Report**: `cve_report.md` - Complete vulnerability analysis
- **Statistics**: `cve_folder_stats_20250725_050504.json` - Collection statistics
- **Cleaned Data**: `cve_patch-cleaned-final.json` - Analysis-ready dataset

## 📝 Notes

- All patch files are in unified diff format
- JSON files contain structured metadata for automated processing
- Commit URLs are preserved for verification and further investigation
- The collection is regularly updated with new CVE discoveries

## 🤝 Contributing

This collection is part of a larger Kubernetes security research project. For questions or contributions, please refer to the main project documentation.

---

*Last Updated: July 2025*
*Total CVE Count: 125*
*Coverage: 2016-2025* 