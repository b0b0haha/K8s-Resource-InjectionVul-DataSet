# RQ2 Root Cause Analysis Codebook

## 1. Overview

### 1.1 Analysis Objective
Identify and classify the root causes of Kubernetes resource injection vulnerabilities based on patch changes, using a two-phase analysis approach: first determine the validation mechanism category, then conduct detailed analysis through multi-dimensional materials.

### 1.2 Key Concepts
- **Missing Validation**: Original code lacks validation mechanisms, patches add validation logic
- **Wrong Validation**: Original code has incorrect validation mechanisms, patches fix validation logic
- **Multi-dimensional Analysis Materials**: Developer explanations, vulnerability descriptions, code comparison analysis

---

## 2. Two-Phase Analysis Process

### Phase 1: Validation Mechanism Category Determination

#### Step 1.1: Patch Code Analysis
**Objective**: Determine whether original validation mechanisms exist

**Missing Validation Identification Criteria**:
- Before patch: No relevant validation logic exists
- After patch: New `validate*`, `check*`, `sanitize*` functions added
- Code characteristics: Patch is purely incremental code, no modification of existing validation logic

**Wrong Validation Identification Criteria**:
- Before patch: Incorrect validation implementation exists
- After patch: Modify or improve existing validation logic
- Code characteristics: Patch modifies existing validation functions or conditional logic

#### Step 1.2: Validation Mechanism Decision Tree
```
Patch Analysis
├── Does original code have validation logic?
│   ├── No validation logic → Missing Validation
│   └── Has validation logic but with defects → Wrong Validation
```

### Phase 2: Multi-dimensional Material Analysis

#### Step 2.1: Multi-dimensional Material Collection
**Material Sources**:
1. **Developer Explanations**: Developer descriptions in patches/commits
2. **Vulnerability Descriptions**: Vulnerability descriptions in CVE reports
3. **Code Analysis**: Comparison of vulnerable version vs. fixed version

**Material Types**:
- Complete vulnerability reports in CVE databases
- GitHub issues and security advisories
- Patch commit descriptions and code changes
- Related discussions and technical analysis

#### Step 2.2: Root Cause Inference Methods
**Inference Priority**:
1. **Developer Explanations** (Highest priority): Direct explanations in patches/commits
2. **Vulnerability Descriptions** (Medium priority): Root cause analysis in reports
3. **Code Analysis** (Basic priority): Technical cause inference through code comparison

---

## 3. Root Cause Classification Framework

### 3.1 Missing Validation

#### 3.1.1 Trust Boundary Shifts

**Local to Cloud Environment**:

**Feature Identification**:
- **Developer Explanation Features**: Mentions "cloud migration", "environment changes", "permission model adjustments"
- **Vulnerability Description Features**: Describes scenarios where local management transitions to cloud user control
- **Code Analysis Features**: Permission subjects change, configuration file access permissions expand

**Specific Manifestations**:

*1. Permission Model Changes*:
- After environment migration, system configuration modification subjects expand from single administrator to all users with API call permissions
- **Example**: CVE-2021-25742 In multi-tenant cluster environments, regular K8s tenants can modify nginx configuration files by creating or updating ingress resources

*2. Resource Design Issues*:
- In K8s multi-tenant scenarios, resource fields need to distinguish between administrator and user permissions, but RBAC permission model only allows permission control at resource level, not field level
- **Example**: CVE-2022-21701 Gateway resources don't strictly distinguish between cluster administrator and tenant user permission boundaries. Listening ports belong to global resources and should be controlled by administrators, but are mixed with TLS certificates, routing rules, and other tenant-level configurations in the same CRD

*3. Architecture Adaptation Issues*:
- Control plane and data plane components sharing file systems lead to sensitive key files being easily accessible
- **Example**: Kubernetes Ingress-NGINX controller adopts architecture where control plane and data plane are co-located in the same Pod. Control plane is granted cluster-level RBAC permissions, and data plane can directly read control plane sensitive data through shared file systems

- Inheriting single-machine environment file system access methods without isolating Pod file systems
- **Example**: CVE-2025-1767 Patch adds protocol whitelist validation for repository field. Original logic only checks repository format without limiting protocol types, exposing local file system access risks in cloud multi-tenant scenarios

- Elastic resource management requirements not met, directly migrating "direct file reading" logic from local single-machine environment to cloud environment
- **Example**: CVE-2022-31030/CVE-2022-1708 No validation of command output file resource usage, attackers can trigger resource exhaustion through legitimate Kube API requests

**Internal to External**:

**Feature Identification**:
- **Developer Explanation Features**: Mentions "external exposure", "interface opening", "threat model changes"
- **Vulnerability Description Features**: Describes internal interfaces accidentally exposed to external users
- **Code Analysis Features**: Internal access models rely on mutual trust, lack additional security measures when exposed externally

**Typical Cases**:
- **Example**: Ingressnightmare series vulnerabilities (CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974) Admission controllers by default only allow cluster internal component access, but cluster administrators misconfigure network policies, exposing admission webhook services to public networks

#### 3.1.2 Validation Responsibility Confusion

**Over-Reliance on Other Resources**:

**Feature Identification**:
- **Developer Explanation Features**: Mentions "assuming other components have validated", "unclear responsibility boundaries"
- **Vulnerability Description Features**: Describes validation responsibility shirking between multiple components
- **Code Analysis Features**: Validation breaks exist in resource reference chains, each component assumes others have validated

**Typical Cases**:
- **Example**: CVE-2024-3177 Secret references can be made through volumemounts fields and env fields. Before patch, only Secret references related to volumeMounts were validated. After patch, Secret reference checks for envFrom fields were added

**Over-Reliance on K8s Security Controls**:

**Feature Identification**:
- **Developer Explanation Features**: Mentions "RBAC already protects", "assuming K8s policies are sufficient"
- **Vulnerability Description Features**: Describes over-trust in built-in security policies
- **Code Analysis Features**: No validation of user permissions for referenced resources, ignoring namespace isolation checks

**Typical Cases**:
- **CVE-2024-43803**: BMO doesn't sufficiently validate Secret resource access permissions, doesn't verify if referenced Secrets are in the same namespace as BareMetalHost
- **CVE-2022-21701**: Istio gateway resource controller doesn't correctly validate Gateway resource fields, attackers inject malicious YAML through annotation fields to bypass RBAC policies
- **CVE-2021-32783**: Attackers access Envoy management interface through carefully crafted ExternalName type Services, bypassing network policy restrictions
- **CVE-2023-39347**: When updating Pods, Cilium incorrectly adopts user-provided Pod label selection to apply policies. Attackers can provide non-existent struct names to bypass network policies

#### 3.1.3 Complex Malicious Content Sources

**Feature Identification**:
- **Developer Explanation Features**: Mentions "complex external integration", "diverse input sources", "difficult to anticipate attacks"
- **Vulnerability Description Features**: Describes complex attack chains from multiple external systems
- **Code Analysis Features**: Extensive integration with third-party systems, malicious inputs undergo complex assembly and transformation processes

**Typical Cases**:
- **CVE-2022-29164**: HTML artifacts as non-traditional input sources, their security processing not fully considered
- **CVE-2022-31036**: Argo CD's repo-server processes multiple Git repository inputs but doesn't implement unified strict validation for different source inputs
- **CVE-2021-37914**: Argo Workflows allows users to dynamically provide parameters for runtime overrides, original template env fields get injected with parameter overrides

### 3.2 Wrong Validation

#### 3.2.1 Overlooked Input Content

**Feature Identification**:
- **Developer Explanation Features**: Mentions "incomplete validation", "missed attack scenarios", "insufficient boundary checks"
- **Vulnerability Description Features**: Describes existing validation bypassed by specific attack techniques
- **Code Analysis Features**: Bypassable validation logic exists, not considering all attack vectors

**Typical Cases**:
- **CVE-2024-7646**: Bypass of CVE-2021-25742
- **CVE-2022-4886**: Bypass of CVE-2021-25745, using Log_format, access_log, Include to bypass field content regex matching validation
- **CVE-2021-25748**: Bypass of CVE-2021-25745
- **CVE-2023-5043**: Bypass of CVE-2021-25742 and CVE-2021-25746
- **CVE-2022-24731**: Bypass of CVE-2022-24348, original resolveSymbolicLinkRecursive function limits recursion depth but doesn't perform root directory boundary checks on resolved paths

#### 3.2.2 Overlooked Input Types

**Feature Identification**:
- **Developer Explanation Features**: Mentions "type confusion", "parsing errors"
- **Vulnerability Description Features**: Describes parsing confusion caused by input types
- **Code Analysis Features**: Fields accept multiple input types, parsing functions handle incorrectly

**Typical Cases**:
- **CVE-2022-24348**: url.ParseRequestURI() function misjudges absolute path format local file paths as legitimate HTTP request URIs, causing critical path security validation to be skipped

#### 3.2.3 Developer Coding Mistakes

**Feature Identification**:
- **Developer Explanation Features**: Mentions "implementation errors", "programming oversights"
- **Vulnerability Description Features**: Describes simple implementation errors
- **Code Analysis Features**: Obvious logic errors, filtering mechanism implementation errors

**Typical Cases**:
- **CVE-2023-6476**: CRI-O filtering logic defect. When checking if annotations belong to restricted lists, code incorrectly removes prefixes from disallowed lists instead of actually matching annotation keys, allowing malicious users to bypass restrictions

---

## 4. Multi-dimensional Analysis Decision Matrix

### 4.1 Material Analysis Priority

| Cause Category | Developer Explanations | Vulnerability Descriptions | Code Analysis | Weight |
|----------------|------------------------|----------------------------|---------------|--------|
| Trust Boundary Shifts | Environment migration, permission changes | Attack scenario changes | Permission subject changes | High |
| Validation Responsibility | Responsibility boundaries, component assumptions | Multi-component interaction | Validation breakpoints | High |
| Complex Content Sources | External integration, attack complexity | Multi-source attack chains | Integration complexity | Medium |
| Overlooked Content | Incomplete validation, attack bypass | Bypass techniques | Validation logic defects | High |
| Input Type Confusion | Type confusion, parsing errors | Parsing issues | Type handling errors | High |
| Coding Mistakes | Implementation errors, programming oversights | Simple errors | Obvious logic errors | Medium |

### 4.2 Comprehensive Judgment Criteria

**Multi-dimensional Consistency Check**:
1. Three material sources point to same cause category → High confidence
2. Two material sources consistent, third not conflicting → Medium confidence
3. Material sources have conflicts → Expert arbitration needed

**Evidence Strength Assessment**:
- **Strong Evidence**: Developer explicit explanation + code analysis support
- **Medium Evidence**: Clear vulnerability description + code feature matching
- **Weak Evidence**: Inference based only on code analysis

---

## 5. Analysis Examples

### 5.1 Missing Validation - CVE-2021-25741

**Phase 1: Validation Mechanism Analysis**
```
Before patch: No input validation logic
After patch: New nginx configuration validation and escaping
→ Determined as Missing Validation
```

**Phase 2: Multi-dimensional Material Analysis**
```
Developer explanation: Commit description mentions "cloud environment requires user input validation"
Vulnerability description: CVE describes scenario where local administrator permissions become cloud user permissions
Code analysis: Local configuration file access permissions expand to cluster user input
→ Comprehensive judgment as Trust Boundary Shifts - Local to Cloud
```

### 5.2 Wrong Validation - CVE-2022-24731

**Phase 1: Validation Mechanism Analysis**
```
Before patch: Depth limitation validation logic exists
After patch: Fix boundary check logic
→ Determined as Wrong Validation
```

**Phase 2: Multi-dimensional Material Analysis**
```
Developer explanation: Commit states "fix path traversal validation bypass"
Vulnerability description: Describes multi-layer path traversal bypassing existing validation
Code analysis: Original validation only checks depth, doesn't check resolved path boundaries
→ Comprehensive judgment as Overlooked Input Content
```

---

## 6. Output Format

```
Phase 1 - Validation Mechanism Analysis:
- Original validation: [Exists/Does not exist]
- Patch type: [Missing Validation/Wrong Validation]
- Code changes: [Key code before/after comparison]

Phase 2 - Multi-dimensional Analysis:
- Developer explanation: [Developer description in patch/commit]
- Vulnerability description: [Relevant description in CVE report]
- Code analysis: [Technical root cause]

Final Classification:
- Primary cause: [Root cause category] - [Subcategory]
- Evidence strength: [Strong/Medium/Weak]
- Confidence: [High/Medium/Low]
- Secondary causes: [Other related causes]
```

---

## 7. Quality Control

### 7.1 Consistency Requirements
- Multiple analysts independently conduct two-phase analysis
- Cross-validate interpretation of multi-dimensional materials
- Resolve divergent cases through expert discussion to reach consensus

### 7.2 Material Completeness Check
- Ensure collection of all available developer explanations
- Verify accuracy and completeness of vulnerability descriptions
- Guarantee technical depth of code comparison analysis

### 7.3 Classification Quality Assurance
- Evidence strength must support classification conclusions
- Multi-dimensional materials must be basically consistent
- Boundary cases require detailed recording of judgment basis 