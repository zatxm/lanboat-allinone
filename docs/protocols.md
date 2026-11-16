# 协议与示例

选择与服务端一致的协议，再复制对应示例修改。示例中的本地地址、演示密码和证书路径需要根据实际环境替换。

| 协议或功能 | 配置示例 |
| --- | --- |
| Shadowsocks | [客户端](../examples/independent-client.json)、[服务端](../examples/independent-server.json) |
| Shadowsocks2022 | [客户端](../examples/independent-ss2022-client.json)、[服务端](../examples/independent-ss2022-server.json) |
| ShadowsocksR | [客户端](../examples/independent-ssr-client.json) |
| VMess | [客户端](../examples/independent-vmess-mux-client.json)、[服务端](../examples/independent-vmess-mux-server.json) |
| VLESS | [客户端](../examples/independent-vless-mux-client.json)、[服务端](../examples/independent-vless-mux-server.json) |
| Trojan | [客户端](../examples/independent-trojan-mux-client.json)、[服务端](../examples/independent-trojan-mux-server.json) |
| Hysteria | [客户端](../examples/independent-hysteria-client.json) |
| Hysteria2 | [客户端](../examples/independent-hysteria2-client.json)、[服务端](../examples/independent-hysteria2-server.json) |
| TUIC4 | [客户端](../examples/independent-tuic4-client.json)、[服务端](../examples/independent-tuic4-server.json) |
| TUIC5 | [客户端](../examples/independent-tuic-client.json)、[服务端](../examples/independent-tuic-server.json) |
| SSH | [客户端](../examples/independent-ssh-client.json) |
| WireGuard | [客户端](../examples/independent-wireguard-client.json)、[服务端](../examples/independent-wireguard-server.json)、[端点](../examples/independent-wireguard-endpoint.json) |
| AmneziaWG | [客户端](../examples/independent-amnezia-client.json)、[3.x配置](../examples/independent-amnezia3-client.json) |
| Brook | [客户端](../examples/independent-brook-client.json)、[QUIC](../examples/independent-brook-quic-client.json) |
| Snell | [服务端](../examples/independent-snell-server.json) |
| Mieru | [TCP](../examples/independent-mieru-tcp-client.json)、[UDP](../examples/independent-mieru-udp-client.json) |
| OpenConnect | [客户端](../examples/independent-openconnect-client.json)、[交互认证](../examples/independent-openconnect-interactive-client.json) |
| TrustTunnel | [客户端](../examples/independent-trusttunnel-h2-client.json) |
| MASQUE | [客户端](../examples/independent-masque-client.json)、[服务端](../examples/independent-masque-server.json) |
| Juicity | [客户端](../examples/independent-juicity-client.json) |
| Naive | [客户端](../examples/independent-naive-client.json)、[HTTP/3](../examples/independent-naive-quic-client.json) |
| Tailscale | [客户端](../examples/independent-tailscale-client.json)、[交互登录](../examples/independent-tailscale-interactive.json)、[子网路由](../examples/independent-tailscale-router.json) |
| Sudoku | [客户端](../examples/independent-sudoku-client.json)、[服务端](../examples/independent-sudoku-server.json) |
| Lua | [客户端](../examples/independent-lua-client.json) |
| ShadowTLS | [v1](../examples/independent-shadowtls1-client.json)、[v2](../examples/independent-shadowtls2-client.json)、[v3](../examples/independent-shadowtls3-client.json) |

SOCKS5、HTTP/HTTPS及Mixed入站可提供本地代理；AnyTLS等其他类型和可用算法由`lanboat-allinone protocols`列出。

## 传输与附加设置

- [XHTTP](../examples/independent-xhttp-advanced-client.json)、[mKCP](../examples/independent-mkcp-client.json)和[通用连接复用](../examples/independent-multiplex-client.json)。
- [Reality](../examples/independent-reality-client.json)、[ECH](../examples/independent-ech-client.json)和[客户端证书](../examples/independent-mtls-client.json)。
- Shadowsocks插件：[混淆](../examples/independent-ss-obfs-client.json)、[v2ray-plugin](../examples/independent-ss-v2ray-ws-client.json)、[KCPTUN](../examples/independent-kcptun-v1-client.json)、[Cloak](../examples/independent-cloak-client.json)、[GOST](../examples/independent-ss-gost-client.json)、[ShadowTLS](../examples/independent-ss-shadowtls-client.json)。

附加设置必须与服务端支持的传输、插件和版本一致。旧算法仅用于连接现有旧节点，新部署优先使用现代AEAD算法及经过验证的TLS配置。

全部示例位于[examples目录](../examples)，可复制后通过`check -c`检查配置。示例并不提供可用的公网服务器。
