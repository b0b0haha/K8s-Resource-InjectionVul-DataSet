# Kubernetes Resource Injection Vulnerability Privileged Operation API Identification Codebook

## 1. Overview

### 1.1 Analysis Objective
This Codebook provides guidance for identifying and classifying privileged operation APIs in Kubernetes resource injection vulnerabilities, focusing on functions where tainted data ultimately flows and executes dangerous operations (sink points).

### 1.2 Key Concept Definitions
- **Privileged Operation API**: Functions where tainted data ultimately flows and executes dangerous operations (sink points)
- **API**: Application Programming Interface with actual system impact capabilities
- **Sink Point**: Final dangerous operation execution point that cannot propagate further downstream

### 1.3 Analysis Scope
- **Strict Limitation**: Only count sink point functions, excluding source points, intermediate propagation functions, or other auxiliary functions
- **Vulnerability-Specific**: Focus on final dangerous operation execution points in resource injection vulnerabilities

---

## 2. Detailed Analysis Process

### Step 1: Fix Location Identification (Sanitizer Location)
**Objective**: Determine the location and logic of security check functions through patch analysis

**Operation Steps**:
1. Carefully read CVE descriptions and vulnerability reports
2. Analyze git diff patch content
3. Identify newly added validation functions, check logic, or filtering mechanisms
4. Record sanitizer function names and file locations

**Key Identification Points**:
- Newly added `validate*`, `check*`, `sanitize*` functions
- Input filtering logic (regex patterns, blacklists/whitelists)
- Error return and exception handling mechanisms

### Step 2: Taint Source Location (Source Identification)
**Objective**: Reverse-engineer vulnerable fields from fix logic to locate the source of tainted data

**Operation Steps**:
1. Analyze field names processed by sanitizer functions
2. Search for assignment locations of these fields in code
3. Confirm fields originate from Kubernetes resource definitions
4. Record complete resource paths (e.g., `spec.containers[].image`)

### Step 3: Data Flow Tracking (Sink Location)
**Objective**: Track the complete propagation path of tainted data from source to final dangerous operation

**Operation Steps**:
1. Start from taint source and trace data propagation paths
2. Record key intermediate variables and function calls
3. Identify functions that ultimately execute dangerous operations
4. Confirm the function is a true sink point (cannot propagate further)

**Tracking Techniques**:
- Focus on variable assignments: `target := source`
- Focus on function parameter passing: `dangerousFunc(source)`
- Focus on struct field propagation: `obj.field = source`
- Focus on interface method calls: `interface.Method(source)`

### Step 4: API Characteristic Confirmation
**Objective**: Confirm whether the sink point function is an API function with actual operational capabilities

### Step 5: API Functional Classification
**Objective**: Classify APIs according to their specific functionality into predefined classification framework

---

## 3. API Identification Standards

### 3.1 Hierarchical Standards for API Judgment

#### 3.1.1 Direct API Call Check (Highest Priority)
**Standard**: Functions directly calling standard library or framework APIs
```go
// ✅ Explicit standard library API calls
cmd := exec.Command("git", args...)     // System command execution
file, err := os.Open(filename)          // File system operation
client.Create(ctx, obj)                 // K8s API call
```

**Judgment Criteria**:
- Direct calls to Go standard libraries like `os.*`, `exec.*`, `net.*`
- Calls to `syscall.*` package system calls
- Use of `unsafe` package for low-level operations
- Calls to `client-go` K8s API clients
- Calls to container runtime APIs (Docker, containerd, etc.)

#### 3.1.2 Function Characteristic Analysis

**a) Function Comment Check**
```go
// ✅ Comments explicitly indicating API nature
// ExecuteCommand runs a system command with given arguments
// CreateResource creates a new Kubernetes resource in the cluster
```

**b) Function Naming Patterns**
- `execute*`, `run*`, `exec*` → Execution operations
- `create*`, `update*`, `delete*` → Resource operations
- `write*`, `read*`, `open*` → File operations
- `parse*`, `render*`, `process*` → Data processing

**c) Parameter and Return Value Characteristics**
```go
// ✅ Typical API signature patterns
func ExecuteCommand(cmd string, args []string) ([]byte, error)
func WriteFile(path string, data []byte) error
func ParseTemplate(template string, data interface{}) (string, error)
```

#### 3.1.3 Functional Impact Assessment
- Function execution changes system state (file system, processes, network, K8s cluster state)
- Interacts with external systems (operating system, file system, network services, databases)
- Has security risks and permission-related operations

### 3.2 API Judgment Decision Tree
```
Is the function an API?
├── Direct standard library/framework API call? ─── YES → Confirm as API
├── Function comments explicitly indicate API? ──── YES → Confirm as API
├── Function name matches API operation pattern? ── YES → Further analysis
├── Parameters/return values match API features? ─ YES → Further analysis
├── Changes system/cluster state? ─────────────── YES → Likely API
├── Interacts with external systems? ──────────── YES → Likely API
└── None of the above ──────────────────────────── NO → Not API, continue tracking
```

---

## 4. Privileged Operation Classification Framework

### 4.1 Command Execution

#### Definition
Operations that execute system commands, scripts, or start processes

#### Subcategories
- **Direct Command Execution**: Execute system commands through container args, command fields
- **Script Execution**: Execute shell scripts, batch files, etc.
- **Process Launch**: Start new system processes or services
- **Privilege Switching**: Switch user identity or escalate execution privileges

#### Standard Library API Examples
```go
// Go standard library
exec.Command()          // Execute system command
exec.CommandContext()   // Command execution with context
os.StartProcess()       // Start process
syscall.Exec()          // System call execution

// Common third-party libraries
dockerClient.ContainerExec()     // Docker container command execution
k8sClient.PodExecCreate()        // Kubernetes Pod command execution
```

#### Identification Keywords
- Function names: `exec*`, `command*`, `run*`, `start*`, `launch*`
- Parameters: `cmd`, `command`, `args`, `executable`
- Package paths: `os/exec`, `syscall`

### 4.2 File System Operations

#### Definition
Operations for reading, writing, mounting file systems

#### Subcategories
- **File I/O Operations**: File reading, writing, creation, deletion operations
- **Directory Mounting**: Mount host directories or storage volumes
- **Path Operations**: Path traversal, symbolic link handling, etc.

#### Standard Library API Examples
```go
// Go standard library - File operations
os.Open()               // Open file
os.Create()             // Create file
os.Remove()             // Delete file
os.Mkdir()              // Create directory
ioutil.ReadFile()       // Read file
ioutil.WriteFile()      // Write file
filepath.Walk()         // Traverse directory

// Go standard library - Mount operations
syscall.Mount()         // Mount file system
syscall.Unmount()       // Unmount file system

// Container-related libraries
dockerClient.CopyToContainer()   // Copy file to container
k8sClient.PVCreate()            // Create persistent volume
```

#### Identification Keywords
- Function names: `open*`, `read*`, `write*`, `create*`, `delete*`, `mount*`, `copy*`
- Parameters: `filename`, `path`, `directory`, `volume`
- Package paths: `os`, `io`, `ioutil`, `filepath`

### 4.3 Network Operations

#### Definition
Operations for network communication and connection establishment

#### Subcategories
- **Network Connections**: Establish TCP/UDP connections
- **HTTP Requests**: Send HTTP/HTTPS requests
- **Service Discovery**: DNS resolution, service registration, etc.

#### Standard Library API Examples
```go
// Go standard library
net.Dial()              // Establish network connection
net.Listen()            // Listen on network port
http.Get()              // HTTP GET request
http.Post()             // HTTP POST request
url.Parse()             // URL parsing

// Third-party libraries
grpc.Dial()             // gRPC connection
client.Do()             // HTTP client request
```

#### Identification Keywords
- Function names: `dial*`, `connect*`, `listen*`, `serve*`, `request*`
- Parameters: `url`, `address`, `port`, `host`
- Package paths: `net`, `net/http`, `net/url`

### 4.4 Kubernetes Resource API Operations

#### Definition
Operations on Kubernetes cluster resources

#### Subcategories
- **Resource CRUD Operations**: Create, read, update, delete K8s resources
- **Resource Queries**: List queries, field selectors, label selectors
- **Resource Status Updates**: Update resource status fields
- **Resource Relationship Handling**: Handle ownerReferences, controller relationships, etc.

#### Standard Library API Examples
```go
// client-go library
client.Create()         // Create resource
client.Get()            // Get resource
client.Update()         // Update resource
client.Delete()         // Delete resource
client.List()           // List resources
client.Watch()          // Watch resource changes
client.Patch()          // Partial update resource

// Specific resource operations
podClient.Create()      // Create Pod
svcClient.Update()      // Update Service
cmClient.Delete()       // Delete ConfigMap
```

#### Identification Keywords
- Function names: `create*`, `get*`, `update*`, `delete*`, `list*`, `watch*`
- Parameters: `ctx`, `obj`, `options`, `namespace`
- Package paths: `k8s.io/client-go`, `sigs.k8s.io/controller-runtime`

### 4.5 Security Configuration Generation

#### Definition
Dynamic generation or modification of security-related configurations

#### Subcategories
- **Security Policy Generation**: Generate RBAC, network policies, etc.
- **Certificate Management**: Certificate generation, rotation, etc.
- **Key Management**: Key generation, storage, etc.

#### Standard Library API Examples
```go
// Cryptography-related
crypto/rand.Read()          // Generate random numbers
crypto/rsa.GenerateKey()    // Generate RSA key
crypto/x509.CreateCertificate() // Create certificate
crypto/tls.Config{}         // TLS configuration

// Kubernetes security-related
rbac.NewRule()              // Create RBAC rule
admission.NewHandler()      // Create admission controller
```

#### Identification Keywords
- Function names: `generate*`, `create*`, `configure*`, `policy*`, `rbac*`
- Parameters: `policy`, `rule`, `certificate`, `key`
- Package paths: `crypto/*`, `k8s.io/api/rbac`

### 4.6 Format Processing

#### Definition
Operations for parsing, processing, and formatting output of complex data formats

#### Subcategories
- **Format Parsing**: Parse structured data like YAML/JSON/XML
- **Template Rendering**: Process configuration templates and variable substitution
- **Formatted Output**: Format data to specific formats and output
- **Data Serialization**: Data format conversion and encoding

#### Standard Library API Examples

**Format Parsing Category**:
```go
// Go standard library
json.Unmarshal()        // JSON parsing
xml.Unmarshal()         // XML parsing
strconv.ParseInt()      // String to integer parsing
url.Parse()             // URL parsing

// Third-party libraries
yaml.Unmarshal()        // YAML parsing (gopkg.in/yaml.v2)
toml.Unmarshal()        // TOML parsing
```

**Formatted Output Category**:
```go
// Go standard library
fmt.Sprintf()           // Format string
fmt.Printf()            // Format print
json.Marshal()          // JSON serialization output
xml.Marshal()           // XML serialization output
log.Printf()            // Formatted log output
template.Execute()      // Template rendering output

// Third-party libraries
yaml.Marshal()          // YAML formatted output
logrus.WithFields()     // Structured log output
zap.Sugar().Infof()     // High-performance formatted log
```

**Template Rendering Category**:
```go
// Go standard library
text/template.Execute() // Text template rendering
html/template.Execute() // HTML template rendering

// Third-party libraries
helm.RenderTemplate()   // Helm template rendering
mustache.Render()       // Mustache template rendering
gin.HTML()              // Web framework template rendering
```

**Data Conversion Category**:
```go
// Go standard library
base64.Encode()         // Base64 encoding
hex.EncodeToString()    // Hexadecimal encoding
gob.Encode()            // Go binary encoding

// Third-party libraries
protobuf.Marshal()      // Protocol Buffer serialization
msgpack.Marshal()       // MessagePack serialization
```

#### Identification Keywords
- **Parsing category**: `parse*`, `unmarshal*`, `decode*`, `deserialize*`
- **Output category**: `format*`, `print*`, `sprintf*`, `marshal*`, `serialize*`
- **Rendering category**: `render*`, `template*`, `execute*`, `generate*`
- **Conversion category**: `encode*`, `convert*`, `transform*`

#### Parameter Characteristics
- **Input parameters**: `data`, `template`, `config`, `manifest`, `format`, `pattern`
- **Output parameters**: `writer`, `buffer`, `output`, `destination`

#### Package Paths
- **Standard library**: `encoding/*`, `text/template`, `html/template`, `fmt`, `log`
- **Third-party libraries**: `gopkg.in/yaml.v2`, `github.com/sirupsen/logrus`

#### Security Risk Description
- **Parsing risks**: Maliciously crafted inputs may cause DoS attacks, memory exhaustion
- **Output risks**: Formatted output may leak sensitive information or be injected with malicious content
- **Template risks**: Template injection may lead to code execution or information disclosure
- **Serialization risks**: Deserialization vulnerabilities may lead to remote code execution

---

## 5. Edge Case Handling

### 5.1 Wrapper Functions
```go
func wrapperFunction() {
    return underlyingAPI()  // ✅ Still counts as API (transitivity)
}
```
**Handling Principle**: If a function is simply a wrapper around an API, it still counts as an API

### 5.2 Utility Functions
```go
func helperFunction() {
    // Only data processing, no external API calls
    return processData()    // ❌ Not an API
}
```
**Handling Principle**: Pure data processing functions don't count as APIs

### 5.3 Composite Functions
```go
func compositeFunction() {
    helperFunction()        // Non-API part
    actualAPI()            // ✅ This part counts as API
}
```
**Handling Principle**: Only count the API parts within

---

## 6. Complete Analysis Example: CVE-2024-10220

### Step 1: Fix Location Identification
```diff
+	if (src.Revision != "") && (src.Directory != "") {
+		cleanedDir := filepath.Clean(src.Directory)
+		if strings.Contains(cleanedDir, "/") || (strings.Contains(cleanedDir, "\\")) {
+			return fmt.Errorf("%q is not a valid directory", src.Directory)
+		}
+	}
```
**Analysis Result**: Fixed path injection vulnerability in `GitRepoVolumeSource`'s `Directory` field

### Step 2: Taint Source Location
**Taint Source**: `spec.Volume.GitRepo.Repository`

### Step 3: Data Flow Tracking
Data propagation chain:
1. `spec.Volume.GitRepo.Repository` → `gitRepoVolumeMounter.source`
2. Construct git command in `SetUpAt` method: `args := []string{"clone", "--", b.source}`
3. `execCommand` executes system command

### Step 4: API Characteristic Confirmation
Analyze `execCommand` function:
```go
func (b *gitRepoVolumeMounter) execCommand(command string, args []string, dir string) ([]byte, error) {
    cmd := b.exec.Command(command, args...)  // 🔍 Key analysis point
    cmd.SetDir(dir)
    return cmd.CombinedOutput()
}
```

**API Identification Process**:
1. **Direct API Call**: ✅ `b.exec.Command()` calls Go standard library `os/exec`
2. **Function Naming**: ✅ `execCommand` clearly indicates command execution
3. **Parameter Characteristics**: ✅ `(command string, args []string, dir string)` matches command execution characteristics
4. **Return Value Characteristics**: ✅ `([]byte, error)` is typical Go API return pattern
5. **Functional Impact**: ✅ Directly executes system commands, may change system state

**Conclusion**: Confirmed as command execution API

### Step 5: API Functional Classification
**Classification Basis**:
- **API Name**: `execCommand` → Clear command execution operation
- **API Function**: Execute system command `git clone`
- **Standard Library Match**: Uses `exec.Command()`, belongs to command execution category

**Final Classification**: **Command Execution**

---

## 7. Quality Control Mechanisms

### 7.1 Classification Consistency Check
- Multiple researchers independently analyze the same vulnerability
- Cross-validate classification results
- Calculate Cohen's Kappa coefficient to ensure consistency

### 7.2 Disagreement Resolution Mechanism
- When classification opinions differ, organize expert discussions
- Introduce third-party experts for arbitration
- Reach consensus based on concrete evidence

### 7.3 Classification Validation Standards
- Each API must have clear code evidence support
- Classification results must be consistent with predefined framework
- Edge cases need special annotation and explanation

---

## 8. Important Notes

### ✅ Functions to Count
- API functions that directly execute dangerous operations
- Final sink points that cannot propagate further downstream
- Operation functions with actual system impact

### ❌ Functions Not to Count
- Intermediate propagation functions (only pass data)
- Data transformation functions (don't execute dangerous operations)
- Validation check functions (sanitizers)
- Auxiliary utility functions (helper functions)

### 🔧 Special Case Handling
- **Wrapper Functions**: If a function is simply a wrapper around an API, it still counts as an API
- **Composite Functions**: If a function contains multiple operations, only count the API parts
- **Conditional Execution**: Even if API calls have conditional restrictions, they still count as potential sink points