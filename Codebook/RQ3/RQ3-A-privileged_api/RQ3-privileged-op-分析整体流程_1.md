## K8s资源注入漏洞关键操作函数分类和统计说明

**要求**：**仅统计K8s资源注入漏洞的sink点函数**，即最终执行危险操作的函数

### 重要说明：
- **关键操作定义**：污点数据最终流向并执行危险操作的函数（sink点）
- **严格限制**：只统计sink点函数，不包括source点、中间传播函数或其他辅助函数
- **漏洞特定**：专注于资源注入漏洞的最终危险操作执行点


###  关键操作的分析流程
step 1： 先查看补丁，定位check的位置 (sanitizer)
step 2: 结合check函数和用于触发漏洞的注入字段定位相对应的资源字段，定位污点源(src)
step 3: 跟踪污点源最终流向的函数操作 (sink)
step 4: 确定sink点是否为API
step 5: 对API进行分类
通过API的名称、API的注释以及API使用的上下文来结合现有的分类框架对API进行分类



示例说明： CVE-2024-10220

step 1： 先查看补丁，定位check的位置 (sanitizer)

这个函数调用 validateNonFlagArgument 来验证 repository 字段。
```
diff --git a/pkg/volume/git_repo/git_repo.go b/pkg/volume/git_repo/git_repo.go
index 995018d900727..b3827b92ad0f0 100644
--- a/pkg/volume/git_repo/git_repo.go
+++ b/pkg/volume/git_repo/git_repo.go
@@ -261,6 +261,12 @@ func validateVolume(src *v1.GitRepoVolumeSource) error {
 	if err := validateNonFlagArgument(src.Directory, "directory"); err != nil {
 		return err
 	}
+	if (src.Revision != "") && (src.Directory != "") {
+		cleanedDir := filepath.Clean(src.Directory)
+		if strings.Contains(cleanedDir, "/") || (strings.Contains(cleanedDir, "\\")) {
+			return fmt.Errorf("%q is not a valid directory, it must not contain a directory separator", src.Directory)
+		}
+	}
 	return nil
 }
```




step 2: 结合check函数和用于触发漏洞的注入字段定位相对应的资源字段，定位污点源(src)
函数在 gitRepoPlugin.NewMounter 方法中，将 spec.Volume.GitRepo.Repository 的值赋给 gitRepoVolumeMounter 结构体的 source 字段。

step 3: 跟踪污点源最终流向的函数操作 (sink)
字段的数据流传播链为： 
- NewMounter 读取 repository 字段 → source 变量

```
func (plugin *gitRepoPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, opts volume.VolumeOptions) (volume.Mounter, error) {
	if err := validateVolume(spec.Volume.GitRepo); err != nil {
		return nil, err
	}

	return &gitRepoVolumeMounter{
		gitRepoVolume: &gitRepoVolume{
			volName: spec.Name(),
			podUID:  pod.UID,
			plugin:  plugin,
		},
		pod:      *pod,
		source:   spec.Volume.GitRepo.Repository,
		revision: spec.Volume.GitRepo.Revision,
		target:   spec.Volume.GitRepo.Directory,
		exec:     exec.New(),
		opts:     opts,
	}, nil
}

```
- SetUpAt 将 source 作为参数传递给 git clone 命令
```
// SetUpAt creates new directory and clones a git repo.
func (b *gitRepoVolumeMounter) SetUpAt(dir string, mounterArgs volume.MounterArgs) error {
	if volumeutil.IsReady(b.getMetaDir()) {
		return nil
	}

	// Wrap EmptyDir, let it do the setup.
	wrapped, err := b.plugin.host.NewWrapperMounter(b.volName, wrappedVolumeSpec(), &b.pod, b.opts)
	if err != nil {
		return err
	}
	if err := wrapped.SetUpAt(dir, mounterArgs); err != nil {
		return err
	}

	args := []string{"clone", "--", b.source}

	if len(b.target) != 0 {
		args = append(args, b.target)
	}
	if output, err := b.execCommand("git", args, dir); err != nil {
		return fmt.Errorf("failed to exec 'git %s': %s: %v",
			strings.Join(args, " "), output, err)
	}

```
- execCommand 执行命令，恶意代码被 shell 解析并执行
```
func (b *gitRepoVolumeMounter) execCommand(command string, args []string, dir string) ([]byte, error) {
	cmd := b.exec.Command(command, args...)
	cmd.SetDir(dir)
	return cmd.CombinedOutput()
}

```
step 4: 确定sink点是否为API
execCommand 直接调用系统的 os/exec 包来执行命令，没有任何沙箱或权限限制。 

step 5: 对API进行分类
execCommand 属于命令执行



### 关键操作类别：

#### 1. 命令执行 (Command Execution)
- **直接命令执行**：通过容器args、command字段执行系统命令
- **脚本执行**：执行shell脚本、批处理文件等
- **进程启动**：启动新的系统进程或服务
- **权限切换**：切换用户身份或提升执行权限



#### 2. 文件系统操作 (File System Operations)
- **文件I/O操作**：文件读取、写入、创建、删除等操作
  - 配置文件读写
  - 日志文件操作
  - 临时文件创建
  - 敏感文件访问
- **目录挂载**：挂载宿主机目录或存储卷
  - hostPath挂载
  - 存储卷绑定
  - 设备文件映射
  - 特权目录访问

#### 3. 资源字段解析 (Resource Field Parsing)
- **YAML/JSON解析**：解析Kubernetes资源定义
- **模板渲染**：处理配置模板和变量替换
- **字段验证**：验证资源字段格式和内容
- **数据类型转换**：字段值的类型转换和格式化

#### 4. K8s资源API操作 (Kubernetes Resource API Operations)
- **资源CRUD操作**：创建、读取、更新、删除K8s资源
- **资源查询**：列表查询、字段选择器、标签选择器
- **资源状态更新**：更新资源status字段
- **资源关系处理**：处理ownerReferences、控制器关系等

#### 5. 配置生成 (Configuration Generation)
- **动态配置生成**：基于模板生成配置文件
- **参数注入**：将用户输入注入到配置中
- **环境变量设置**：设置容器环境变量
- **配置合并**：合并多个配置源

#### 6. 格式化输出 (Formatted Output)
- **日志输出格式化**：格式化日志信息输出
- **状态信息显示**：格式化显示资源状态
- **错误信息处理**：格式化错误消息
- **调试信息输出**：输出调试和诊断信息


