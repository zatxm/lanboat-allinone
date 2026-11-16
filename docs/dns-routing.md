# DNS与路由

## DNS解析

```json
{
  "dns": {
    "servers": [
      {"type": "udp", "tag": "bootstrap", "server": "1.1.1.1"},
      {"type": "https", "tag": "secure", "server": "cloudflare-dns.com", "domain_resolver": "bootstrap", "path": "/dns-query", "tls": {"enabled": true}}
    ],
    "final": "secure",
    "cache_capacity": 4096
  }
}
```

将此片段合并到现有配置。`final`选择默认解析器；加密DNS服务器使用域名时，`domain_resolver`提供引导解析。DNS服务器的`detour`可以指定代理出站。

本地DNS服务、分域、DoQ和高级应答配置可参考[DNS示例](../examples/independent-dns-records.json)、[DoQ客户端](../examples/independent-dns-quic-client.json)和[并行解析](../examples/independent-dns-parallel.json)。

FakeIP可为A/AAAA查询返回虚拟地址，由核心在转发时恢复域名。[TUN示例](../examples/independent-tun.json)包含FakeIP、远程DNS和DNS劫持的组合配置。

## 路由分流

规则按顺序匹配。下面的片段将指定域名直连，其他流量交给`proxy`：

```json
{
  "route": {
    "rules": [{"domain_suffix": ["example.cn"], "action": "route", "outbound": "direct"}],
    "final": "proxy"
  }
}
```

需要在`outbounds`中配置`direct`和`proxy`。常见条件包括`domain`、`domain_suffix`、`ip_cidr`、`port`、`network`和`rule_set`。`action: "reject"`拒绝流量；DNS接管使用`action: "hijack-dns"`。

进程、用户、网卡和邻居设备规则依赖操作系统能够提供相应信息，可参考[用户分流](../examples/independent-user-route.json)和[进程分流](../examples/independent-linux-process-route.json)。

## 规则集

核心不内置GeoIP/GeoSite数据，也不会默认下载规则。通过`inline`、本地文件或远程URL配置需要的规则集。

本地规则集示例片段：

```json
{
  "route": {
    "rule_set": [{"type": "local", "tag": "local-domains", "format": "source", "path": "./rules/domains.json"}],
    "rules": [{"rule_set": ["local-domains"], "action": "route", "outbound": "direct"}],
    "final": "proxy"
  }
}
```

`rules/domains.json`内容：

```json
{"version":4,"rules":[{"domain_suffix":["example.cn"]}]}
```

可以将JSON规则编译为SRS，以减少重复解析：

```bash
lanboat-allinone rule-set compile -o rules/domains.srs rules/domains.json
```

使用SRS时将规则集的`format`改为`binary`、`path`改为对应`.srs`文件。AdGuard文本规则可使用`rule-set convert -type adguard -o rules/filter.srs filter.txt`转换。

[Lanboat规则数据](https://github.com/zatxm/geoip)提供可下载的规则包。解压后选择需要的SRS文件，在配置中显式引用；下载和定时更新由你的部署方式安排。

## 代理分组

`selector`用于从多个节点中选择一个，`urltest`根据探测结果选择节点。配置中的`outbounds`填写组内节点的tag，组本身也有tag，可作为`route.final`或某条规则的`outbound`。

节点的`detour`表示先经过另一个出站建立连接，可用于代理链；它与分组选择是不同功能。为节点和分组设置清晰的tag，避免循环引用。
