# Kubernetes资源注入漏洞特权操作API识别Codebook

## 1. 总体说明

### 1.1 分析目标
本Codebook用于指导Kubernetes资源注入漏洞中特权操作API的识别和分类，专注于污点数据最终流向并执行危险操作的函数（sink点）。

### 1.2 关键概念定义
- **特权操作API**：污点数据最终流向并执行危险操作的函数（sink点）
- **API**：具有实际系统影响能力的应用程序编程接口
- **Sink点**：不可再向下传播的最终危险操作执行点

### 1.3 分析范围
- **严格限制**：仅统计sink点函数，不包括source点、中间传播函数或其他辅助函数
- **漏洞特定**：专注于资源注入漏洞的最终危险操作执行点

---

## 2. 分析流程详述

### Step 1: 定位修复位置 (Sanitizer定位)
**目标**：通过补丁分析确定安全检查函数的位置和逻辑

**操作步骤**：
1. 仔细阅读CVE描述和漏洞报告
2. 分析git diff补丁内容
3. 识别新增的验证函数、检查逻辑或过滤机制
4. 记录sanitizer函数名称和所在文件位置

**关键识别点**：
- 新增的`validate*`、`check*`、`sanitize*`函数
- 输入过滤逻辑（如正则表达式、黑白名单）
- 错误返回和异常处理机制

### Step 2: 污点源定位 (Source识别)
**目标**：结合修复逻辑反推被修复的漏洞字段，定位污点数据的来源

**操作步骤**：
1. 分析sanitizer函数处理的字段名称
2. 在代码中搜索该字段的赋值位置
3. 确认字段来源于Kubernetes资源定义
4. 记录完整的资源路径（如`spec.containers[].image`）

### Step 3: 数据流跟踪 (Sink定位)
**目标**：跟踪污点数据从source到最终危险操作的完整传播路径

**操作步骤**：
1. 从污点源开始，追踪数据的传播路径
2. 记录关键的中间变量和函数调用
3. 识别最终执行危险操作的函数
4. 确认该函数为真正的sink点（不可再传播）

**跟踪技巧**：
- 关注变量赋值：`target := source`
- 关注函数参数传递：`dangerousFunc(source)`
- 关注结构体字段传播：`obj.field = source`
- 关注接口方法调用：`interface.Method(source)`

### Step 4: API特征确认
**目标**：确认sink点函数是否为具有实际操作能力的API函数

### Step 5: API功能分类
**目标**：根据API的具体功能将其归类到预定义的分类框架中

---

## 3. API识别标准

### 3.1 API判断的层次化标准

#### 3.1.1 直接API调用检查（优先级最高）
**标准**：函数直接调用标准库或框架API
```go
// ✅ 明确的标准库API调用
cmd := exec.Command("git", args...)     // 系统命令执行
file, err := os.Open(filename)          // 文件系统操作
client.Create(ctx, obj)                 // K8s API调用
```

**判断标准**：
- 直接调用`os.*`、`exec.*`、`net.*`等Go标准库
- 调用`syscall.*`包的系统调用
- 使用`unsafe`包进行底层操作
- 调用`client-go`的K8s API客户端
- 调用容器运行时API（Docker、containerd等）

#### 3.1.2 函数特征分析

**a) 函数注释检查**
```go
// ✅ 注释明确说明API性质
// ExecuteCommand runs a system command with given arguments
// CreateResource creates a new Kubernetes resource in the cluster
```

**b) 函数命名模式**
- `execute*`, `run*`, `exec*` → 执行类操作
- `create*`, `update*`, `delete*` → 资源操作
- `write*`, `read*`, `open*` → 文件操作
- `parse*`, `render*`, `process*` → 数据处理

**c) 参数和返回值特征**
```go
// ✅ API典型签名模式
func ExecuteCommand(cmd string, args []string) ([]byte, error)
func WriteFile(path string, data []byte) error
func ParseTemplate(template string, data interface{}) (string, error)
```

#### 3.1.3 功能影响评估
- 函数执行会改变系统状态（文件系统、进程、网络、K8s集群状态）
- 与外部系统交互（操作系统、文件系统、网络服务、数据库）
- 具有安全风险和权限相关操作

### 3.2 API判断决策树
```
函数是否为API？
├── 直接调用标准库/框架API？ ────── YES → 确认为API
├── 函数注释明确说明API性质？ ───── YES → 确认为API
├── 函数名符合API操作模式？ ────── YES → 进一步分析
├── 参数/返回值符合API特征？ ───── YES → 进一步分析
├── 会改变系统/集群状态？ ──────── YES → 很可能是API
├── 与外部系统交互？ ──────────── YES → 很可能是API
└── 以上都不符合 ──────────────── NO → 非API，继续跟踪
```

---

## 4. 特权操作分类框架

### 4.1 命令执行 (Command Execution)

#### 定义
执行系统命令、脚本或启动进程的操作

#### 子类别
- **直接命令执行**：通过容器args、command字段执行系统命令
- **脚本执行**：执行shell脚本、批处理文件等
- **进程启动**：启动新的系统进程或服务
- **权限切换**：切换用户身份或提升执行权限

#### 标准库API示例
```go
// Go标准库
exec.Command()          // 执行系统命令
exec.CommandContext()   // 带上下文的命令执行
os.StartProcess()       // 启动进程
syscall.Exec()          // 系统调用执行

// 常见第三方库
dockerClient.ContainerExec()     // Docker容器命令执行
k8sClient.PodExecCreate()        // Kubernetes Pod命令执行
```

#### 识别关键词
- 函数名：`exec*`, `command*`, `run*`, `start*`, `launch*`
- 参数：`cmd`, `command`, `args`, `executable`
- 包路径：`os/exec`, `syscall`

### 4.2 文件系统操作 (File System Operations)

#### 定义
对文件系统进行读写、挂载等操作

#### 子类别
- **文件I/O操作**：文件读取、写入、创建、删除等操作
- **目录挂载**：挂载宿主机目录或存储卷
- **路径操作**：路径遍历、符号链接处理等

#### 标准库API示例
```go
// Go标准库 - 文件操作
os.Open()               // 打开文件
os.Create()             // 创建文件
os.Remove()             // 删除文件
os.Mkdir()              // 创建目录
ioutil.ReadFile()       // 读取文件
ioutil.WriteFile()      // 写入文件
filepath.Walk()         // 遍历目录

// Go标准库 - 挂载操作
syscall.Mount()         // 挂载文件系统
syscall.Unmount()       // 卸载文件系统

// 容器相关库
dockerClient.CopyToContainer()   // 复制文件到容器
k8sClient.PVCreate()            // 创建持久卷
```

#### 识别关键词
- 函数名：`open*`, `read*`, `write*`, `create*`, `delete*`, `mount*`, `copy*`
- 参数：`filename`, `path`, `directory`, `volume`
- 包路径：`os`, `io`, `ioutil`, `filepath`

### 4.3 网络操作 (Network Operations)

#### 定义
执行网络通信、连接建立等操作

#### 子类别
- **网络连接**：建立TCP/UDP连接
- **HTTP请求**：发送HTTP/HTTPS请求
- **服务发现**：DNS解析、服务注册等

#### 标准库API示例
```go
// Go标准库
net.Dial()              // 建立网络连接
net.Listen()            // 监听网络端口
http.Get()              // HTTP GET请求
http.Post()             // HTTP POST请求
url.Parse()             // URL解析

// 第三方库
grpc.Dial()             // gRPC连接
client.Do()             // HTTP客户端请求
```

#### 识别关键词
- 函数名：`dial*`, `connect*`, `listen*`, `serve*`, `request*`
- 参数：`url`, `address`, `port`, `host`
- 包路径：`net`, `net/http`, `net/url`

### 4.4 Kubernetes资源API操作 (Kubernetes Resource API Operations)

#### 定义
对Kubernetes集群资源进行操作

#### 子类别
- **资源CRUD操作**：创建、读取、更新、删除K8s资源
- **资源查询**：列表查询、字段选择器、标签选择器
- **资源状态更新**：更新资源status字段
- **资源关系处理**：处理ownerReferences、控制器关系等

#### 标准库API示例
```go
// client-go库
client.Create()         // 创建资源
client.Get()            // 获取资源
client.Update()         // 更新资源
client.Delete()         // 删除资源
client.List()           // 列出资源
client.Watch()          // 监听资源变化
client.Patch()          // 部分更新资源

// 特定资源操作
podClient.Create()      // 创建Pod
svcClient.Update()      // 更新Service
cmClient.Delete()       // 删除ConfigMap
```

#### 识别关键词
- 函数名：`create*`, `get*`, `update*`, `delete*`, `list*`, `watch*`
- 参数：`ctx`, `obj`, `options`, `namespace`
- 包路径：`k8s.io/client-go`, `sigs.k8s.io/controller-runtime`

### 4.5 安全配置生成 (Security Configuration Generation)

#### 定义
动态生成或修改安全相关配置

#### 子类别
- **安全策略生成**：生成RBAC、网络策略等
- **证书管理**：证书生成、轮换等
- **密钥管理**：密钥生成、存储等

#### 标准库API示例
```go
// 加密相关
crypto/rand.Read()          // 生成随机数
crypto/rsa.GenerateKey()    // 生成RSA密钥
crypto/x509.CreateCertificate() // 创建证书
crypto/tls.Config{}         // TLS配置

// Kubernetes安全相关
rbac.NewRule()              // 创建RBAC规则
admission.NewHandler()      // 创建准入控制器
```

#### 识别关键词
- 函数名：`generate*`, `create*`, `configure*`, `policy*`, `rbac*`
- 参数：`policy`, `rule`, `certificate`, `key`
- 包路径：`crypto/*`, `k8s.io/api/rbac`

### 4.6 格式化处理 (Format Parsing)

#### 定义
解析、处理和格式化输出复杂数据格式的操作

#### 子类别
- **格式解析**：解析YAML/JSON/XML等结构化数据
- **模板渲染**：处理配置模板和变量替换
- **格式化输出**：格式化数据为特定格式并输出
- **数据序列化**：数据格式转换和编码

#### 标准库API示例

**格式解析类**：
```go
// Go标准库
json.Unmarshal()        // JSON解析
xml.Unmarshal()         // XML解析
strconv.ParseInt()      // 字符串解析为整数
url.Parse()             // URL解析

// 第三方库
yaml.Unmarshal()        // YAML解析 (gopkg.in/yaml.v2)
toml.Unmarshal()        // TOML解析
```

**格式化输出类**：
```go
// Go标准库
fmt.Sprintf()           // 格式化字符串
fmt.Printf()            // 格式化打印
json.Marshal()          // JSON序列化输出
xml.Marshal()           // XML序列化输出
log.Printf()            // 格式化日志输出
template.Execute()      // 模板渲染输出

// 第三方库
yaml.Marshal()          // YAML格式化输出
logrus.WithFields()     // 结构化日志输出
zap.Sugar().Infof()     // 高性能格式化日志
```

**模板渲染类**：
```go
// Go标准库
text/template.Execute() // 文本模板渲染
html/template.Execute() // HTML模板渲染

// 第三方库
helm.RenderTemplate()   // Helm模板渲染
mustache.Render()       // Mustache模板渲染
gin.HTML()              // Web框架模板渲染
```

**数据转换类**：
```go
// Go标准库
base64.Encode()         // Base64编码
hex.EncodeToString()    // 十六进制编码
gob.Encode()            // Go二进制编码

// 第三方库
protobuf.Marshal()      // Protocol Buffer序列化
msgpack.Marshal()       // MessagePack序列化
```

#### 识别关键词
- **解析类**：`parse*`, `unmarshal*`, `decode*`, `deserialize*`
- **输出类**：`format*`, `print*`, `sprintf*`, `marshal*`, `serialize*`
- **渲染类**：`render*`, `template*`, `execute*`, `generate*`
- **转换类**：`encode*`, `convert*`, `transform*`

#### 参数特征
- **输入参数**：`data`, `template`, `config`, `manifest`, `format`, `pattern`
- **输出参数**：`writer`, `buffer`, `output`, `destination`

#### 包路径
- **标准库**：`encoding/*`, `text/template`, `html/template`, `fmt`, `log`
- **第三方库**：`gopkg.in/yaml.v2`, `github.com/sirupsen/logrus`

#### 安全风险说明
- **解析风险**：恶意构造的输入可能导致DoS攻击、内存耗尽
- **输出风险**：格式化输出可能泄露敏感信息或被注入恶意内容
- **模板风险**：模板注入可能导致代码执行或信息泄露
- **序列化风险**：反序列化漏洞可能导致远程代码执行

---

## 5. 边界情况处理

### 5.1 包装函数
```go
func wrapperFunction() {
    return underlyingAPI()  // ✅ 仍然算API（传递性）
}
```
**处理原则**：如果函数只是对API的简单包装，仍然算作API

### 5.2 工具函数
```go
func helperFunction() {
    // 只做数据处理，不调用外部API
    return processData()    // ❌ 不算API
}
```
**处理原则**：纯数据处理函数不算API

### 5.3 组合函数
```go
func compositeFunction() {
    helperFunction()        // 非API部分
    actualAPI()            // ✅ 这部分算API
}
```
**处理原则**：只统计其中的API部分

---

## 6. 完整分析示例：CVE-2024-10220

### Step 1: 定位修复位置
```diff
+	if (src.Revision != "") && (src.Directory != "") {
+		cleanedDir := filepath.Clean(src.Directory)
+		if strings.Contains(cleanedDir, "/") || (strings.Contains(cleanedDir, "\\")) {
+			return fmt.Errorf("%q is not a valid directory", src.Directory)
+		}
+	}
```
**分析结果**：修复了`GitRepoVolumeSource`的`Directory`字段的路径注入漏洞

### Step 2: 污点源定位
**污点源**：`spec.Volume.GitRepo.Repository`

### Step 3: 数据流跟踪
数据传播链：
1. `spec.Volume.GitRepo.Repository` → `gitRepoVolumeMounter.source`
2. `SetUpAt`方法中构造git命令：`args := []string{"clone", "--", b.source}`
3. `execCommand`执行系统命令

### Step 4: API特征确认
分析`execCommand`函数：
```go
func (b *gitRepoVolumeMounter) execCommand(command string, args []string, dir string) ([]byte, error) {
    cmd := b.exec.Command(command, args...)  // 🔍 关键分析点
    cmd.SetDir(dir)
    return cmd.CombinedOutput()
}
```

**API识别过程**：
1. **直接API调用**：✅ `b.exec.Command()`调用Go标准库`os/exec`
2. **函数命名**：✅ `execCommand`明确表示执行命令
3. **参数特征**：✅ `(command string, args []string, dir string)`符合命令执行特征
4. **返回值特征**：✅ `([]byte, error)`是典型的Go API返回模式
5. **功能影响**：✅ 直接执行系统命令，可能改变系统状态

**结论**：确认为命令执行API

### Step 5: API功能分类
**分类依据**：
- **API名称**：`execCommand` → 明确的命令执行操作
- **API功能**：执行系统命令`git clone`
- **标准库匹配**：使用`exec.Command()`，属于命令执行类别

**最终分类**：**命令执行 (Command Execution)**

---

## 7. 质量控制机制

### 7.1 分类一致性检查
- 多名研究人员独立分析同一漏洞
- 交叉验证分类结果
- 计算Cohen's Kappa系数确保一致性

### 7.2 分歧解决机制
- 当分类意见不一致时，组织专家讨论
- 引入第三方专家进行仲裁
- 基于具体证据达成共识

### 7.3 分类验证标准
- 每个API必须有明确的代码证据支持
- 分类结果必须与预定义框架一致
- 边界情况需要特别标注和说明

---

## 8. 注意事项

### ✅ 需要统计的函数
- 直接执行危险操作的API函数
- 不可再向下传播的最终sink点
- 具有实际系统影响的操作函数

### ❌ 不需要统计的函数
- 中间传播函数（只是传递数据）
- 数据转换函数（不执行危险操作）
- 验证检查函数（sanitizer）
- 辅助工具函数（helper functions）

### 🔧 特殊情况处理
- **包装函数**：如果函数只是对API的简单包装，仍然算作API
- **组合函数**：如果函数包含多个操作，只统计其中的API部分
- **条件执行**：即使API调用有条件限制，仍然算作潜在的sink点