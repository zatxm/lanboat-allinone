# TUN使用

TUN模式接管系统IP流量，适合不能单独设置SOCKS5/HTTP代理的应用。普通本地代理无需TUN。

## 开始使用

1. 复制[TUN示例](../examples/independent-tun.json)。
2. 将`proxy`出站改成自己的服务器地址、端口和密码。
3. 执行`lanboat-allinone check -c tun.json`。
4. 使用系统所需权限运行`lanboat-allinone run -c tun.json`。

示例同时保留`127.0.0.1:2080`本地代理。`auto_route`自动添加接管路由；DNS部分通过FakeIP和加密上游配合工作。

停止时发送正常停止信号，程序清理自身创建的设备和路由。更改全局路由前应保留能够恢复网络的本地终端。

## Linux

需要TUN设备和相应网络管理权限，通常使用root或按部署方式授予所需权限。默认使用系统TUN接口。

启用`auto_redirect`时，还需要`nft`命令及对应内核功能。作为局域网网关时，需由系统允许IP转发和防火墙转发。普通客户端接管本机流量无需配置为网关。

`dns_mode: "hijack"`接管DNS流量；`dns_mode: "native"`需要可用的systemd-resolved接口。`dns_mode: "routed"`配置系统DNS，由路由中的`hijack-dns`规则接管查询。可以在该规则前设置应用自身的直连规则，避免引导DNS循环。程序不会覆盖`/etc/resolv.conf`。

## Windows

以管理员身份运行。TUN需要对应架构的官方签名`wintun.dll`，放在可执行文件同一目录。驱动可从[Wintun官网](https://www.wintun.net/)获取。

## macOS

以具备网络管理权限的身份运行，使用系统utun接口。接口名留空时自动选择；指定时使用`utun`加数字。系统DNS设置采用临时会话，正常退出后撤销。

## 排障

- 能连接本地代理但TUN失败：先检查权限、驱动和系统设备。
- 接管后服务器也无法连接：检查物理出口、服务器地址及默认路由，避免流量回到TUN自身。
- DNS异常：先确认上游服务器、引导解析及`detour`出站可用。
- 自定义规则未生效：检查规则顺序、引用tag和规则集路径。

Linux是当前主要实测平台；Windows/macOS已有实现与交叉构建，系统设备、路由和DNS行为仍需在你的目标环境确认。
