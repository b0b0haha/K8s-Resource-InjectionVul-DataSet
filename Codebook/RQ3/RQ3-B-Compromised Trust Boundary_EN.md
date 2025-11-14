# RQ3-B Trust Boundary Compromise Analysis Codebook

## 1. Overview

### 1.1 Analysis Objective
This Codebook provides guidance for identifying and classifying trust boundary compromises in Kubernetes resource injection vulnerabilities, focusing on how attackers break through trust boundaries in Kubernetes architecture via resource injection vulnerabilities.

### 1.2 Key Concept Definitions
- **Trust Boundary**: Security isolation boundaries between different components or layers in Kubernetes architecture
- **Trust Boundary Compromise**: Attackers crossing security boundaries that should be isolated through resource injection vulnerabilities
- **Architectural Layers**: Different system layers including control plane, data plane, host, external networks, etc.

### 1.3 Analysis Scope
Based on the trust boundary classification in Figure 3a of the paper, focusing on 6 main types of trust boundary compromises

---

## 2. Trust Boundary Classification Framework

### 2.1 Data Plane (Container) to Host

#### Definition
Container escape through resource injection in the data plane, bypassing container isolation mechanisms to access host resources

#### Attack Mechanisms
- Malicious Pod annotation injection of system properties
- Container configuration injection of dangerous mount points
- Privileged container configuration abuse

#### Typical Case Examples
- **CVE-2024-3154**: Injecting systemd properties (such as ExecStart) through malicious Pod annotations, bypassing container isolation

#### Identification Characteristics
- Involves injection of Pod configuration fields
- Ultimately affects host system services
- Bypasses container runtime security mechanisms

### 2.2 Data Plane to Control Plane

#### Definition
Gaining access to or modifying control plane content stored in the data plane through resource injection in the data plane

#### Attack Mechanisms
- Accessing service account tokens
- Reading control plane configuration files
- Utilizing shared storage to access sensitive information

#### Typical Case Examples
- **CVE-2021-25741** & **CVE-2021-25745**: As shown in Figure 2 of the paper, accessing service account token directories through Ingress resource injection

#### Identification Characteristics
- Data plane components accessing control plane credentials
- Gaining control plane privileges through configuration files or tokens
- Cross-plane privilege escalation

### 2.3 Inter-Control Plane Components

#### Definition
Exploiting malicious content injected by one control plane component to probe or manipulate other control plane components

#### Attack Mechanisms
- SSRF attacks probing internal services
- Inter-component communication hijacking
- Configuration propagation pollution

#### Typical Case Examples
- **CVE-2022-29164**: SSRF attacks propagating among control plane components

#### Identification Characteristics
- Abnormal network communication between components
- Malicious propagation of configuration or data between components
- Unauthorized access to internal APIs

### 2.4 Multi-Tenant Isolation

#### Definition
Breaking namespace isolation through malicious resource references to access other tenants' resources

#### Attack Mechanisms
- Cross-namespace resource references
- Permission validation bypass
- Resource reference chain attacks

#### Typical Case Examples
- **CVE-2024-43803**: Cross-namespace Secret access discussed in Section V-A2a

#### Identification Characteristics
- Cross-namespace resource access
- Tenant isolation policy failures
- Unauthorized resource references

### 2.5 External to Internal Cluster

#### Definition
Attackers exposing internal cluster components to external access through resource injection

#### Attack Mechanisms
- Malicious services exposing internal resources
- Network policy bypass
- Internal API externalization

#### Typical Case Examples
- **CVE-2021-32783**: Creating malicious ExternalName services linked to Ingress routes, enabling unauthorized external access to internal resources

#### Identification Characteristics
- Internal services unexpectedly exposed externally
- Network boundaries being breached
- External traffic accessing internal resources

### 2.6 Control Plane to Data Plane

#### Definition
Compromised controllers distributing malicious workloads and configurations to the data plane

#### Attack Mechanisms
- Controller logic pollution
- Malicious resource deployment
- Configuration propagation attacks

#### Typical Case Examples
- **CVE-2022-21701**: Attackers create malicious Gateway objects, which the Istiod controller processes and uses to deploy associated resources (such as Pods), propagating malicious workloads across the data plane

#### Identification Characteristics
- Abnormal controller behavior
- Malicious configuration propagation to data plane
- Batch deployment of abnormal resources

---

## 3. Trust Boundary Analysis Methods

### 3.1 Identification Steps

#### Step 1: Determine Attack Starting Point
- Identify the resource type and field where malicious injection occurs
- Determine the architectural layer where injection takes place
- Analyze the attacker's initial permission scope

#### Step 2: Track Attack Path
- Trace the propagation path of malicious data
- Identify components and services crossed
- Record permission changes and escalation processes

#### Step 3: Determine Compromised Boundary
- Compare against the 6 trust boundary types
- Identify permission contrasts before and after attack
- Determine the specific boundary type compromised

#### Step 4: Assess Impact Scope
- Analyze new permissions gained by attacker
- Evaluate overall impact on system security
- Identify potential further attack paths

### 3.2 Classification Decision Criteria

```
Trust Boundary Compromise Type Judgment:
├── Attack starting point in data plane?
│   ├── YES → Affects host? ────────── YES → Data Plane to Host
│   └── YES → Accesses control plane resources? ── YES → Data Plane to Control Plane
├── Attack starting point in control plane?
│   ├── YES → Affects other control plane components? ── YES → Inter-Control Plane Components
│   └── YES → Propagates to data plane? ──── YES → Control Plane to Data Plane  
├── Cross-namespace access? ──────────── YES → Multi-Tenant Isolation
└── Internal resources externally exposed? ────── YES → External to Internal Cluster
```

---

## 4. Analysis Examples

### 4.1 CVE-2021-25741 Example Analysis

#### Attack Scenario
- **Attack Starting Point**: configuration-snippet annotation in Ingress resource
- **Injection Content**: Malicious nginx configuration directives
- **Attack Path**: Ingress → nginx configuration → file system access
- **Compromised Boundary**: Data plane to control plane

#### Analysis Process
1. **Starting Point Confirmation**: Attack begins with Ingress resource in data plane
2. **Path Tracking**: Malicious configuration written to nginx config file, nginx execution exposes service account token
3. **Boundary Identification**: From nginx container in data plane accessing service account token in control plane
4. **Impact Assessment**: Gained cluster administrator privileges, can control entire cluster

#### Classification Result
**Data Plane to Control Plane**

---

## 5. Quality Control

### 5.1 Consistency Check
- Multiple analysts independently analyze the same case
- Cross-validate classification results
- Record disagreements and resolution processes

### 5.2 Validation Standards
- Each classification must have clear attack path support
- Boundary compromises must have concrete evidence of permission changes
- Impact scope assessment must be based on actual attack effects

### 5.3 Edge Case Handling
- **Multiple Boundary Compromises**: Select the primary boundary with greatest impact
- **Indirect Compromises**: Focus on direct boundary crossings
- **Permission Ambiguity**: Classify based on actual attack effects

---

## 6. Important Notes

### ✅ Key Metrics to Focus On
- Permission comparison before and after attack
- Specific architectural boundaries crossed
- Actual degree of security impact

### ❌ Concepts Not to Confuse
- Technical methods vs trust boundary compromises
- Intermediate steps vs final boundary compromises
- Theoretical possibilities vs actual compromises

### 🔧 Special Case Handling
- **Chain Attacks**: Identify boundary compromises at each stage
- **Permission Accumulation**: Focus on final permission boundaries reached
- **Defense Bypass**: Focus on analyzing compromised trust assumptions