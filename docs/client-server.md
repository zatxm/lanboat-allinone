# 客户端与服务端

## 本地代理

最简单的客户端配置：

```json
{
  "log": {"level": "info"},
  "inbounds": [{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": 1080}],
  "outbounds": [{"type": "shadowsocks", "tag": "proxy", "server": "proxy.example.com", "server_port": 8388, "method": "aes-256-gcm", "password": "replace-with-your-password"}],
  "route": {"final": "proxy"}
}
```

保存为`client.json`，检查后运行：

```bash
lanboat-allinone check -c client.json
lanboat-allinone client -c client.json
```

将应用的SOCKS5或HTTP代理设置为`127.0.0.1:1080`。服务器协议、密码和加密方式必须与远端一致。

需要允许局域网其他设备连接时，将本地监听地址改成局域网IP，并为入站设置`users`：

```json
{"inbounds":[{"type":"mixed","tag":"local","listen":"192.168.1.10","listen_port":1080,"users":[{"username":"lanboat","password":"replace-with-a-random-password"}]}]}
```

上述片段只展示入站，实际配置仍需包含出站及路由。局域网设备填写该IP和认证信息。

## 部署服务端

[基础服务端示例](../examples/independent-server.json)与客户端示例可以配对使用。修改以下内容：

1. `listen`：远程服务使用实际网卡IP或`0.0.0.0`。
2. `listen_port`：服务监听端口，确保防火墙允许连接。
3. `password`及协议参数：客户端和服务端保持一致。
4. `outbounds`：服务端通常使用`direct`访问目标。

```bash
lanboat-allinone check -c server.json
lanboat-allinone server -c server.json
```

使用UDP协议时同时放行UDP。普通代理监听不需要管理员权限，使用小于1024的端口或TUN时按系统要求授权。

## Hysteria2

使用[客户端示例](../examples/independent-hysteria2-client.json)和[服务端示例](../examples/independent-hysteria2-server.json)。

服务端填写`users[].password`、`tls.certificate_path`、`tls.key_path`，并放行监听端口的UDP。客户端填写`server`、`server_port`、`password`和`tls.server_name`。

有受信任证书时，客户端通常使用系统证书校验。使用自己的CA或自签名证书时，在客户端`tls.certificate_path`指定相应证书；示例中的`./server.crt`就是此用途。`server_name`应与证书中的名称匹配。

## TLS和密钥

- 服务端证书及私钥由`certificate_path`、`key_path`指定。
- 客户端的`server_name`用于证书名称校验和SNI。
- Reality、ECH、WireGuard等使用各自的密钥字段，参照对应示例。
- 使用`lanboat-allinone generate reality-keypair`或`generate ech-keypair public.example.com`生成对应密钥；生成结果需要妥善保存。

程序不会替换示例中的演示密码，也不会自动把本地监听改为公网监听。
