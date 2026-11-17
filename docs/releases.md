# 下载与运行

## 选择程序文件

在[Releases页面](https://github.com/zatxm/lanboat-allinone/releases)下载对应的可执行文件，无需解压：

| 系统 | 架构 | 文件名 |
| --- | --- | --- |
| Windows | Intel/AMD 64位 | `lanboat-allinone-windows-amd64.exe` |
| Windows | ARM64 | `lanboat-allinone-windows-arm64.exe` |
| Linux | Intel/AMD 64位 | `lanboat-allinone-linux-amd64` |
| Linux | ARM64 | `lanboat-allinone-linux-arm64` |
| macOS | Intel | `lanboat-allinone-macos-amd64` |
| macOS | Apple Silicon | `lanboat-allinone-macos-arm64` |

macOS版本是命令行程序。Linux/macOS下载后先授予执行权限，例如：

```bash
chmod +x lanboat-allinone-macos-arm64
./lanboat-allinone-macos-arm64 version
```

也可将文件重命名为`lanboat-allinone`，后续文档中的命令使用该名称。Windows重命名时保留`.exe`后缀。

## 校验下载文件

每个程序都有同名`.sha256`文件，还提供汇总`SHA256SUMS`。

- Linux：`sha256sum -c lanboat-allinone-linux-amd64.sha256`。
- macOS：`shasum -a 256 lanboat-allinone-macos-arm64`。
- Windows PowerShell：`Get-FileHash .\lanboat-allinone-windows-amd64.exe -Algorithm SHA256`。

将结果与下载的校验值比较，实际文件名按系统和架构调整。

## 准备配置并运行

复制[客户端配置](../examples/independent-client.json)或[服务端配置](../examples/independent-server.json)，修改服务器地址、端口、密码等参数。配置不是可执行文件的一部分，需要单独保存。

以Windows客户端为例：

```powershell
.\lanboat-allinone-windows-amd64.exe check -c client.json
.\lanboat-allinone-windows-amd64.exe client -c client.json
```

Linux/macOS使用`./文件名`执行相同命令。按`Ctrl+C`停止程序。

常规代理运行方法见[客户端与服务端](client-server.md)。TUN需要相应系统权限；Windows还需在程序旁放置官方签名的对应架构`wintun.dll`，详见[TUN使用](tun.md)。
