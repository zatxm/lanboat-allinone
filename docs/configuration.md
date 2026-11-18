# 配置说明

程序读取JSON文件。运行前使用`lanboat-allinone check -c config.json`检查格式、字段和引用关系；检查成功没有输出。

## 主要部分

| 字段 | 用途 |
| --- | --- |
| `inbounds` | 接收应用或远程客户端连接 |
| `outbounds` | 选择直连、代理节点或代理分组 |
| `endpoints` | WireGuard、Tailscale等端点配置 |
| `route` | 路由规则、规则集和默认出站 |
| `dns` | DNS解析器、DNS规则与缓存 |
| `log` | 日志级别及输出路径 |
| `experimental` | 可选控制接口、持久化缓存等功能 |

每个需要引用的对象应设置唯一`tag`。例如`route.final: "proxy"`引用出站中`tag: "proxy"`的节点。程序会拒绝未知字段和无效引用；不同协议的必填项见[协议示例](protocols.md)。

## 监听与认证

本地代理通常监听`127.0.0.1`，避免向其他设备开放。局域网或远程访问需要修改监听地址、配置认证，并放行相应端口。

端口范围为1–65535。已有程序占用相同地址和端口时，启动会报错。

## 日志

```json
{"log":{"level":"info","output":"./logs/lanboat.log","timestamp":true}}
```

将此片段合并到配置顶层，先创建日志目录，例如`mkdir -p logs`。省略`output`时日志输出到终端；`disabled: true`关闭日志；`level`可选`trace`、`debug`、`info`、`warn`、`error`、`fatal`、`panic`（`trace`等同`debug`）；`timestamp: true`在每行前加本地时间。排障时临时将`level`改为`debug`，完成后恢复`info`。

连接日志主要用于记录协议、目标地址、出站和错误；HTTPS通常只能识别目标主机，不能读取加密的网页路径或请求正文。诊断日志可能包含目标域名、IP等信息，分享前请脱敏。

日志格式与sing-box一致，每行一条文本，终端、日志文件和Clash API的`/logs`内容相同（`/logs`不含时间和级别前缀）：

```text
+0800 2026-11-18 17:29:28 INFO [1 0ms] inbound/mixed[mixed-in]: inbound connection from 127.0.0.1:7798
+0800 2026-11-18 17:29:28 INFO [1 0ms] inbound/mixed[mixed-in]: inbound connection to example.com:443
+0800 2026-11-18 17:29:28 DEBUG [1 0ms] router: match[1] domain_suffix=example.com => route(proxy)
+0800 2026-11-18 17:29:28 INFO [1 38ms] outbound/vless[proxy]: outbound connection to example.com:443
+0800 2026-11-18 17:29:40 DEBUG [1 12.30s] connection: connection closed (upload 1.5 KB, download 3.0 MB)
```

`[1 38ms]`为连接ID和从入站接受起的耗时，同一连接的各行共享ID。未设置`timestamp`时，终端输出为`INFO[0012]`（启动后的秒数），文件输出只有级别。终端支持颜色时级别和连接ID会着色，设置环境变量`NO_COLOR`可关闭。

## 文件与持久化

配置、证书、私钥、规则集和日志的相对路径以程序启动时的工作目录为基准。跨目录运行时建议使用绝对路径。程序不会默认把所有数据写入某个固定主目录。

需要保存DNS与FakeIP缓存时，可以添加：

```json
{"experimental":{"cache_file":{"enabled":true,"path":"./data/cache.db","store_dns":true,"store_fakeip":true}}}
```

缓存并非节点配置备份。迁移到其他设备时，应另外保存配置文件、证书及规则文件。

## 常驻运行

在Linux上可以由服务管理器运行程序。设置明确的工作目录，启动命令使用可执行文件和配置文件的绝对路径。修改配置后先执行`check`，再重启对应实例。

停止前台程序使用`Ctrl+C`；后台实例通过服务管理器发送正常停止信号，使缓存和系统资源得到清理。
