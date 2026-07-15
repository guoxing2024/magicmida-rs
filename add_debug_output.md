# 添加调试输出方案

由于调试器难以使用，我们在 Bootstrap 代码中添加文件输出来追踪执行。

## 修改方案

在 Bootstrap 代码中添加：
1. 调用 CreateFileW 创建调试文件
2. 在关键点写入状态码
3. 调用 CloseHandle 关闭文件

## 状态码
- 0x01: TLS 回调进入
- 0x02: GetProcessHeap 成功
- 0x03: HeapAlloc 成功
- 0x04: memcpy 完成
- 0x05: 容器更新完成
- 0x06: TLS 回调返回

## 实现位置
在 container_bootstrap.rs 的 build_stub_code 函数中添加文件写入代码

