# RQ1 Vulnerable Field Characteristic Analysis Codebook

## 1. General Description

### 1.1 Analysis Objectives
Based on vulnerability patches, vulnerability information, and exploitation technical details, accurately identify and classify vulnerable fields in Kubernetes resource injection vulnerabilities, conducting systematic analysis from two dimensions: location characteristics and functional characteristics.

### 1.2 Key Concepts
- **Vulnerable Fields**: Kubernetes resource fields that become attack vectors for resource injection attacks
- **Location Characteristics**: The position of fields in Kubernetes resource structure (metadata, spec, status)
- **Functional Characteristics**: The specific functional purposes and processing methods of fields in component implementations

### 1.3 Analysis Principles
- Determine affected fields based on **patch changes** and **vulnerability exploitation details**
- Combine **field semantics** and **component implementation** for functional classification
- Consider **K8s resource structure** and **application-specific functionality**

---

## 2. Field Identification Methods

### 2.1 Field Identification Process

#### Step 1: Patch Analysis to Determine Fields
**Objective**: Identify fields that are fixed in vulnerability patches

**Identification Methods**:
- Analyze validation logic added or modified in patches
- Find field paths directly mentioned in patches
- Identify affected resource types and field names

**Example**:
```go
// CVE-2021-25741 patch analysis
// Patch path: pkg/apis/networking/v1/ingress.go
// Affected field: metadata.annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
```

#### Step 2: Vulnerability Information Confirmation
**Objective**: Confirm fields through CVE descriptions and security advisories

**Confirmation Methods**:
- Review resource fields mentioned in CVE descriptions
- Analyze fields used in PoC code
- Combine attack vector descriptions to determine injection points

#### Step 3: Exploitation Technical Details Verification
**Objective**: Confirm field purposes through specific exploitation techniques

**Verification Methods**:
- Analyze how attack payloads utilize specific fields
- Understand how field values are processed and executed by components
- Determine the role of fields in the attack chain

---

## 3. Field Location Classification Framework

### 3.1 Resource Metadata (metadata)

#### Definition
Contains resource identification and configuration information in the metadata section, typically used for resource management and controller identification

#### Subcategories

**Basic Information Fields**:
- **Field Examples**: apiVersion, kind, name, namespace, uid, generation
- **Characteristics**: System management fields, typically should be immutable
- **Vulnerability Patterns**: Incorrectly allowing users to modify system management fields
- **Typical Cases**: UID field injection in CVE-2025-1098

**Labels**:
- **Field Examples**: metadata.labels.*
- **Characteristics**: Key-value pairs used for resource selection and grouping
- **Vulnerability Patterns**: Affecting resource selection logic through label injection
- **Typical Cases**: Bypassing network policies through Pod labels in CVE-2023-39347

**Annotations**:
- **Field Examples**: metadata.annotations.*
- **Characteristics**: Store non-identifying metadata, typically used for configuring extended functionality
- **Vulnerability Patterns**: Annotation values are directly used for configuration generation or command execution
- **Typical Cases**: Nginx configuration annotation injection in CVE-2021-25741

#### Identification Criteria
- Field path starts with `metadata.`
- Fields used for resource identification, classification, or metadata storage
- Typically set by users during resource creation

### 3.2 Resource Specification (spec)

#### Definition
Defines user-desired resource state configuration, containing core functional definitions of resources

#### Characteristics
- Field path starts with `spec.`
- Users can directly configure and modify
- Contains main functional parameters of resources

#### Vulnerability Patterns
- Specification field values directly used for system operations
- Lack of adequate input validation and filtering
- Field values propagate to privileged operations

#### Typical Cases
- CVE-2021-25745: spec.rules[].http.paths[].path field injection
- CVE-2024-10220: spec.volumes[].gitRepo.repository field injection
- CVE-2022-21701: spec.servers[].port field and related configuration injection

#### Identification Criteria
- Field path starts with `spec.`
- Defines core functional configuration of resources
- Directly affects resource behavior and operations

### 3.3 Resource Status (status)

#### Definition
Records the current actual state of resources, typically maintained by controllers

#### Characteristics
- Field path starts with `status.`
- Theoretically users should not directly modify
- Updated by system components and controllers

#### Vulnerability Patterns
- Incorrectly granting users write permissions to status fields
- Status field values are trusted and used by other components
- Lack of permission checks for status field modifications

#### Typical Cases
- CVE-2020-8554: status.loadBalancer.ingress.ip field permission configuration error

#### Identification Criteria
- Field path starts with `status.`
- Vulnerabilities originate from permission configuration errors
- Inappropriate user write permission grants

---

## 4. Field Functional Classification Framework

### 4.1 Path Matching Fields

#### Definition
Fields that control resource access paths, URL routing, file paths, etc.

#### Functional Characteristics
- Used for path parsing and matching
- Affect network routing or file system access
- Typically involve path traversal or URL construction

#### Typical Fields
- `ingress.spec.rules[].host`: Hostname matching
- `ingress.spec.rules[].http.paths[].path`: URL path matching
- `volumeMount.mountPath`: Container mount path
- `hostPath.path`: Host machine path

#### Vulnerability Patterns
- Path traversal attacks (../../../etc/passwd)
- Malicious URL construction
- File system access bypass

#### Typical Cases
- CVE-2021-25745: Nginx configuration injection through path field
- CVE-2022-24731: Path traversal through path field

#### Identification Criteria
- Field names contain keywords like path, host, url, route
- Field values used for path parsing or matching logic
- Vulnerabilities involve path traversal or URL construction

### 4.2 Command Execution Fields

#### Definition
Fields that directly or indirectly execute system commands, scripts, or programs

#### Functional Characteristics
- Field values ultimately passed to command execution functions
- Affect container startup or lifecycle management
- Involve script execution or program calls

#### Typical Fields
- `container.command`: Container startup command
- `container.args`: Command line arguments
- `lifecycle.postStart.exec.command`: Lifecycle hook command
- `lifecycle.preStop.exec.command`: Pre-stop execution command

#### Vulnerability Patterns
- Command injection and parameter injection
- Shell script injection
- Environment variable injection affecting command execution

#### Typical Cases
- CVE-2024-10220: Git command parameter injection through gitRepo field
- CVE-2022-1708/CVE-2022-31030: Lifecycle hook command injection

#### Identification Criteria
- Field names contain keywords like command, args, exec, script
- Field values used for constructing or executing system commands
- Vulnerabilities involve command injection or code execution

### 4.3 Resource Reference Fields

#### Definition
Fields that reference other Kubernetes resources or external resources

#### Functional Characteristics
- Establish relationships between resources
- Used for data sharing and configuration passing
- Involve cross-resource data flow

#### Typical Fields
- `configMapRef`: ConfigMap resource reference
- `secretRef`: Secret resource reference
- `serviceAccountName`: ServiceAccount reference
- `volumes[].gitRepo.repository`: External Git repository reference

#### Vulnerability Patterns
- Cross-namespace resource access
- External resource reference injection
- Resource reference chain attacks

#### Typical Cases
- CVE-2024-43803: Cross-namespace Secret reference
- CVE-2024-3177: envFrom field Secret reference bypass
- CVE-2021-41254: Validation break in resource reference chain

#### Identification Criteria
- Field names contain keywords like Ref, Name, Reference
- Field values used for referencing other resources
- Vulnerabilities involve resource access permissions or reference validation

### 4.4 Application-Specific Function Fields

#### Definition
Fields specific to certain applications or controllers, implementing application-specific business logic

#### Subclassifications

**4.4.1 Intra-application Similarity**
- **Definition**: Fields with similar functions within the same application exhibit identical vulnerability patterns
- **Characteristics**: Different fields in the same application implement similar functions, having identical security flaws
- **Examples**: configuration-snippet annotation and path field in CVE-2021-25741 and CVE-2021-25745 for Ingress

**4.4.2 Inter-application Similarity**
- **Definition**: Fields implementing the same function in different applications exhibit similar vulnerability patterns
- **Characteristics**: Different applications implementing the same function have similar security flaws
- **Examples**: lifecycle.preStop and lifecycle.postStart fields in CRI-O and containerd (CVE-2022-1708 and CVE-2022-31030)

#### Functional Characteristics
- Implement application-specific business logic
- Field semantics closely related to application functionality
- Typically require understanding field purposes in conjunction with application documentation

#### Typical Fields
- `nginx.ingress.kubernetes.io/configuration-snippet`: Nginx configuration snippet
- `istio.io/rev`: Istio version identifier
- `spec.servers[].port`: Gateway port configuration
- `io.kubernetes.cri-o.UnifiedCgroup`: CRI-O resource limit annotation

#### Vulnerability Patterns
- Application-specific configuration injection
- Business logic bypass
- Security flaws in functional extension points

#### Identification Criteria
- Fields belong to specific application or controller extended functionality
- Field naming contains application or component identifiers
- Require understanding field purposes in conjunction with application functional documentation

---

## 5. Analysis Decision Matrix

### 5.1 Location Classification Decision Tree
```
Field Location Analysis
├── Does field path start with metadata.?
│   ├── YES → metadata category
│   │   ├── labels.* → label fields
│   │   ├── annotations.* → annotation fields
│   │   └── name/uid/namespace → basic information fields
├── Does field path start with spec.? → spec category
├── Does field path start with status.? → status category
└── Other paths → special cases, require specific analysis
```

### 5.2 Functional Classification Decision Tree
```
Field Function Analysis
├── Is field used for path/URL/file processing? → Path matching fields
├── Is field used for command/script execution? → Command execution fields
├── Is field used for referencing other resources? → Resource reference fields
├── Does field belong to application-specific functionality? → Application-specific function fields
│   ├── Do other fields in same application have similar vulnerabilities? → Intra-application similarity
│   └── Do similar fields in other applications have similar vulnerabilities? → Inter-application similarity
└── Cannot classify → Need to create new category or re-analyze
```

### 5.3 Comprehensive Analysis Matrix

| Location\Function | Path Matching | Command Execution | Resource Reference | Application-Specific |
|-------------------|---------------|-------------------|-------------------|---------------------|
| metadata | Annotation path configuration | Annotation command injection | ServiceAccount reference | Application-specific annotations |
| spec | Path specification fields | Container command fields | Resource reference fields | Application configuration fields |
| status | Path status fields | - | Status reference fields | Application status fields |

---

## 6. Analysis Examples

### 6.1 CVE-2021-25741 Field Analysis

**Field Identification**:
- **Affected Field**: `metadata.annotations["nginx.ingress.kubernetes.io/configuration-snippet"]`
- **Resource Type**: Ingress
- **Identification Basis**: Patch added validation logic for this annotation

**Location Classification**:
- **Classification Result**: metadata - annotations
- **Classification Basis**: Field path is metadata.annotations.*

**Functional Classification**:
- **Classification Result**: Application-specific function field - Intra-application similarity
- **Classification Basis**: nginx.ingress.kubernetes.io prefix indicates Nginx Ingress controller specific functionality, exhibiting similar configuration injection vulnerability patterns as the path field in CVE-2021-25745

### 6.2 CVE-2024-10220 Field Analysis

**Field Identification**:
- **Affected Field**: `spec.volumes[].gitRepo.repository`
- **Resource Type**: Pod/Volume
- **Identification Basis**: Patch added protocol validation for gitRepo.repository field

**Location Classification**:
- **Classification Result**: spec
- **Classification Basis**: Field path is spec.volumes.*

**Functional Classification**:
- **Classification Result**: Resource reference field
- **Classification Basis**: repository field used for referencing external Git repository resources, vulnerability involves security validation of external resource references

---

## 7. Quality Control

### 7.1 Field Identification Verification
- Must confirm fields based on specific patch code
- Verify field purposes through vulnerability descriptions and PoC
- Combine component implementation to understand field processing logic

### 7.2 Classification Consistency Check
- Location classification based on actual position of fields in K8s resource structure
- Functional classification based on specific purposes of fields in components
- Multiple analysts cross-validate classification results

### 7.3 Boundary Case Handling
- **Multi-functional Fields**: Classify by primary function
- **Composite Field Paths**: Classify by most specific path level
- **New Field Types**: Establish new categories and record classification criteria 