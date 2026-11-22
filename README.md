# Lanboat All-in-One

轻量的多协议网络工具，集客户端、服务端、TUN、DNS和路由分流于一个可执行文件。可用于本地代理、远程代理服务和系统流量接管。

## 功能

- **一个程序，两种角色**：通过配置选择客户端或服务端，也可以同时运行多个入站和出站。
- **多种协议**：Shadowsocks、VMess、VLESS、Trojan、Hysteria、Hysteria2、TUIC、SOCKS5、HTTP/HTTPS、WireGuard、SSH、Brook等。
- **路由分流**：按域名、IP、端口和规则集选择代理、直连或拒绝，支持代理分组。
- **DNS管理**：UDP、TCP、加密DNS、FakeIP、缓存和分域解析。
- **TUN模式**：接管系统流量，无需逐个应用设置代理。

完整协议列表可运行`lanboat-allinone protocols`查看。常用配置见[使用文档](docs/README.md)和[配置示例](examples)。

## 安装

从[Releases](https://github.com/zatxm/lanboat-allinone/releases)下载对应系统与架构的可执行文件，无需解压：

| 系统 | 架构 | 文件 |
| --- | --- | --- |
| Windows | amd64、arm64 | `.exe`可执行文件 |
| Linux | amd64、arm64 | 原生可执行文件 |
| macOS | Intel amd64、Apple Silicon arm64 | 原生可执行文件 |

[下载、校验和运行说明](docs/releases.md)。Linux/macOS下载后需先执行`chmod +x 文件名`，然后按配置启动。

也可使用Go1.27.4或更新版本从源码构建：

```bash
git clone https://github.com/zatxm/lanboat-allinone.git
cd lanboat-allinone
bash scripts/build.sh
./build/lanboat-allinone version
```

生成的程序位于`build/lanboat-allinone`，可复制到任意目录运行。Windows直接构建：

```powershell
go build -trimpath -ldflags "-s -w" -o lanboat-allinone.exe ./cmd/lanboat-allinone
```

Linux是当前主要验证平台。Windows和macOS的TUN权限、驱动及系统要求见[TUN使用](docs/tun.md)。

## 作为客户端

复制[客户端示例](examples/independent-client.json)，填写自己的服务器地址、端口和密码：

```bash
cp examples/independent-client.json client.json
./build/lanboat-allinone check -c client.json
./build/lanboat-allinone client -c client.json
```

示例在`127.0.0.1:1080`提供SOCKS5和HTTP代理。运行后，在浏览器或其他应用中将代理地址设置为`127.0.0.1`、端口设置为`1080`。

按`Ctrl+C`停止。该模式不会自动修改系统代理设置；需要接管系统流量时使用[TUN模式](docs/tun.md)。

## 作为服务端

复制[服务端示例](examples/independent-server.json)，设置协议、监听地址、端口和密码：

```bash
cp examples/independent-server.json server.json
./build/lanboat-allinone check -c server.json
./build/lanboat-allinone server -c server.json
```

示例默认只监听本机。远程连接时，将`listen`改为服务器实际地址或`0.0.0.0`，在防火墙放行对应TCP/UDP端口，并将示例密码替换为自己的随机密码。

Hysteria2等TLS协议还需配置证书，见[客户端与服务端](docs/client-server.md)。

## 常用命令

| 命令 | 用途 |
| --- | --- |
| `version` | 查看版本 |
| `protocols` | 查看协议及功能列表 |
| `check -c config.json` | 检查配置，不启动服务 |
| `run -c config.json` | 按配置启动 |
| `client -c client.json` | 启动客户端配置 |
| `server -c server.json` | 启动服务端配置 |
| `help` | 查看命令帮助 |

`run`、`client`和`server`使用相同的配置格式，实际角色由入站、出站及路由决定。

## 使用文档

- [客户端与服务端](docs/client-server.md)：本地代理、远程连接、Hysteria2和证书。
- [配置说明](docs/configuration.md)：监听、出站、日志和数据文件。
- [DNS与路由](docs/dns-routing.md)：解析器、分流、规则集和代理分组。
- [TUN使用](docs/tun.md)：系统接管、平台要求和权限。
- [协议与示例](docs/protocols.md)：按协议查找配置。
- [常见问题](docs/troubleshooting.md)：配置错误、连接失败和日志排查。
- [下载与运行](docs/releases.md)：选择程序文件、校验和启动。

提交问题时请提供程序版本、操作系统、错误日志和已脱敏的配置。请删除密码、私钥、认证密钥和访问令牌。
