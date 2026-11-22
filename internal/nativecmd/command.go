package nativecmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zatxm/lanboat-allinone/v26/native"
)

// Execute is shared by the standalone command and command-line integration tests.
func Execute(ctx context.Context, args []string, out io.Writer) error {
	if handled, err := native.RunNetworkNamespaceWorker(args); handled {
		return err
	}
	if handled, err := native.RunTailscaleSSHWorker(args); handled {
		return err
	}
	if len(args) == 0 {
		args = []string{"help"}
	}
	switch args[0] {
	case "help", "-h", "--help":
		_, err := fmt.Fprintln(out, "lanboat-allinone <run|client|server|check> -c config.json [--auth-stdio]\nlanboat-allinone <version|protocols>\nlanboat-allinone masque-probe -c config.json -outbound proxy [-timeout 15s] [-peer IPv6]\nlanboat-allinone sudoku-forward -url ws[s]://host/path [-listen 127.0.0.1:port] [-ca file]\nlanboat-allinone relay-bind -c config.json -outbound proxy -listen 127.0.0.1:8080 -target 127.0.0.1:80 -network tcp\nlanboat-allinone rule-set <compile|convert> -o output.srs input\nlanboat-allinone generate ech-keypair public-name\nlanboat-allinone generate cloak-keypair\nlanboat-allinone generate reality-keypair\nlanboat-allinone generate reality-mldsa65-keypair\nlanboat-allinone generate sudoku-keypair\nlanboat-allinone generate sudoku-<split|public> -key-file private.txt")
		return err
	case "generate":
		if len(args) >= 2 && (args[1] == "sudoku-keypair" || args[1] == "sudoku-split" || args[1] == "sudoku-public") {
			return generateSudoku(args[1:], out)
		}
		if len(args) == 2 && args[1] == "reality-mldsa65-keypair" {
			seed, public, err := native.GenerateRealityMLDSA65KeyPair()
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(map[string]string{"mldsa65_seed": seed, "mldsa65_verify": public})
		}
		if len(args) == 2 && args[1] == "reality-keypair" {
			private, public, err := native.GenerateRealityKeyPair()
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(map[string]string{"private_key": private, "public_key": public})
		}
		if len(args) == 2 && args[1] == "cloak-keypair" {
			identity, err := native.GenerateCloakIdentity()
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(identity)
		}
		if len(args) != 3 || args[1] != "ech-keypair" {
			return errors.New("usage: generate ech-keypair public-name | generate cloak-keypair | generate reality-keypair | generate reality-mldsa65-keypair")
		}
		config, key, err := native.GenerateECHKeyPair(args[2])
		if err != nil {
			return err
		}
		if _, err = out.Write(config); err != nil {
			return err
		}
		_, err = out.Write(key)
		return err
	case "relay-bind":
		return executeRelayBind(ctx, args[1:], out)
	case "masque-probe":
		return executeMasqueProbe(ctx, args[1:], out)
	case "sudoku-forward":
		return executeSudokuForward(ctx, args[1:], out)
	case "rule-set":
		return executeRuleSet(args[1:], out)
	case "version":
		_, err := fmt.Fprintln(out, "lanboat-allinone "+native.Version)
		return err
	case "protocols":
		return json.NewEncoder(out).Encode([]map[string]any{
			{"type": "certificate-provider", "providers": []string{"acme", "tailscale", "cloudflare-origin-ca"}, "shared": true, "inline": true, "renewal": true, "persistent_cache": true, "acme_challenges": []string{"http-01", "tls-alpn-01", "dns-01"}, "dns01_providers": []string{"cloudflare", "alidns", "acmedns"}},
			{"type": "reality", "client": true, "server": true, "tls_version": "1.3", "hybrid_key_exchange": true, "mldsa65": true, "fallback": true, "client_hello_replay_protection": true, "browser_fingerprint": false, "transports": []string{"tcp", "ws", "httpupgrade", "http", "grpc", "xhttp"}},
			{"type": "direct", "client": true, "server": true, "tcp": true, "udp": true, "destination_override": true},
			{"type": "mixed", "server": true, "tcp": true, "udp": true},
			{"type": "socks", "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": true, "authentication": "username/password"},
			{"type": "http", "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": false, "tls": true},
			{"type": "xhttp", "client": true, "server": true, "http_versions": []int{1, 2, 3}, "modes": []string{"auto", "packet-up", "stream-up", "stream-one"}, "padding": true, "placements": true, "download_split": true, "xmux": true},
			{"type": "shadowtls", "client": true, "server": true, "versions": []int{1, 2, 3}, "tcp": true, "udp": false, "inbound_detour": true, "handshake_sni_backends": true, "wildcard_sni": true},
			{"type": "openconnect", "client": true, "server": true, "tcp": true, "udp": true, "icmp_echo": true, "tls": true, "transport": "cstp", "dtls": true, "dtls_version": "1.2", "dtls_versions": []string{"1.2", "1.3"}, "dtls13_psk_dhe": true, "dtls13_openconnect_binding": "lanboat-extension", "dtls13_cipher_suites": []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}, "dtls_psk": true, "legacy_dtls": false, "dtls_cipher_suites": []string{"PSK-AES128-GCM-SHA256", "PSK-AES256-GCM-SHA384", "PSK-CHACHA20-POLY1305", "PSK-AES128-CCM", "PSK-AES256-CCM", "PSK-AES128-CCM8", "PSK-AES256-CCM8", "PSK-AES128-CBC-SHA", "PSK-AES256-CBC-SHA", "PSK-AES128-CBC-SHA256", "PSK-AES256-CBC-SHA384"}, "authentication": "username/password", "group": true, "tun_device_required": false, "pushed_dns": true, "split_dns": true, "search_domains": true, "interactive_auth_forms": true, "static_form_entries": true, "http_negotiate_provider": true, "host_scan_callback": true, "session_rekey_new_tunnel": true, "dtls_channel_renewal": true, "client_sso": []string{"single-sign-on-v2", "single-sign-on-external-browser"}, "strap_channel_binding": true, "system_interface": true, "pushed_routes": true, "system_routes_auto_import": true},
			{"type": "masque", "client": true, "server": true, "tcp": true, "udp": true, "icmp_echo": true, "http_versions": []int{1, 2, 3}, "modes": []string{"connect-ip", "connect-udp"}, "capsules": true, "http_datagrams": true, "compatible_endpoints": []string{"masque-client", "masque-server"}, "version_fallback": true, "multi_version_listener": true, "scoped_uri": true, "uri_query_templates": true, "dns_configuration": true, "pref64_configuration": true, "dns64": true, "configuration_draft": "draft-ietf-masque-connect-ip-dns-07", "cleartext_http_versions": []int{1, 2}, "client_advertise_routes": true, "server_reverse_dial": true, "reverse_icmp": true, "system_interface": true, "connection_settings": true, "path_mtu_discovery": true, "initial_packet_size": true, "udp_nat": true, "end_to_end_mtu_probe": true, "link_local_echo": true},
			{"type": "mieru", "client": true, "server": true, "tcp": true, "udp": true, "carriers": []string{"tcp", "udp"}, "user_hint": true, "traffic_pattern": true, "low_entropy_modes": []int{0, 1, 2, 3, 4}, "multiplexing": true},
			{"type": "sudoku", "client": true, "server": true, "tcp": true, "udp": true, "carrier": "tcp", "udp_over_tcp": true, "authentication": "shared-key", "user_whitelist": true, "user_identity": "shared-secret-protected-hash", "independent_user_proof": false, "user_bandwidth_limits": true, "monthly_data_quotas": true, "persistent_usage": true, "max_users_per_inbound": 1024, "private_key_formats": []string{"master-scalar", "split-scalar"}, "public_key_recovery": true, "key_split": true, "aead": []string{"none", "aes-128-gcm", "chacha20-poly1305"}, "directional_layouts": true, "custom_table": true, "custom_tables": true, "table_rotation": "per-connection", "table_probe_max_bytes": 65536, "max_custom_tables": 16, "packed_downlink": true, "packed_uplink": true, "reverse_tcp": true, "reverse_http": true, "reverse_websocket": true, "reverse_websocket_forward": true, "reverse_max_publishers_per_entry": 64, "reverse_max_routes_per_entry": 256, "reverse_max_routes_per_publisher": 64, "reverse_max_connections": 128, "multiplexing": true, "multiplex_protocol": "kip", "http_mask": true, "http_mask_modes": []string{"legacy", "ws", "stream", "poll", "auto"}},
			{"type": "naive", "client": true, "server": true, "tcp": true, "udp_over_tcp": true, "tls": true, "http_versions": []int{2, 3}, "padding": true, "browser_fingerprint": false, "congestion_control": "new_reno"},
			{"type": "shadowsocks", "client": true, "server": true, "tcp": true, "udp": true, "ota": true, "plugins": map[string][]string{"obfs-local": {"http", "tls"}, "v2ray-plugin": {"websocket", "quic", "hysteria2"}, "gost": {"mws", "mwss", "mtls", "ws", "wss", "tls"}, "shadow-tls": {"1", "2", "3"}, "kcptun": {"1", "2"}, "cloak": {"direct", "cdn", "websocket"}}, "ciphers": native.ShadowsocksMethods(), "transports": []string{"tcp", "ws", "httpupgrade", "http", "grpc", "quic", "xhttp", "mkcp"}},
			{"type": "trojan", "vision": "lanboat-extension-v1", "vision_flow": "xtls-rprx-vision", "vision_external_interoperability": false, "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": true, "tls": true, "multiplex": "trojan-go-smux-v1", "shadowsocks_encryption": []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}, "transports": []string{"tcp", "ws", "httpupgrade", "http", "grpc", "quic", "xhttp", "mkcp"}},
			{"type": "lua", "client": true, "server": false, "tcp": true, "udp": false, "independent_interpreter": true, "callback_api": "backend-v1", "builtins": []string{"http-backend.lua", "lightsword-backend.lua", "trojan-backend.lua"}, "custom_scripts": true, "tls": true, "sip003_plugins": true, "full_lua_standard_library": false},
			{"type": "vless", "vision": true, "flow": []string{"xtls-rprx-vision"}, "vision_xudp": true, "reality": true, "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": true, "xudp_server": true, "tls": true, "multiplex": "mux-cool", "transports": []string{"tcp", "ws", "httpupgrade", "http", "grpc", "quic", "xhttp", "mkcp"}},
			{"type": "vmess", "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": true, "tls": true, "multiplex": "mux-cool", "authentication": "AEAD", "legacy_md5": true, "authenticated_length": true, "global_padding": true, "security": []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}, "transports": []string{"tcp", "ws", "httpupgrade", "http", "grpc", "quic", "xhttp", "mkcp"}},
			{"type": "anytls", "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": true, "tls": true, "session_reuse": true, "padding_updates": true},
			{"type": "relay", "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": true, "tls": true, "bind": true, "bind_networks": []string{"tcp", "udp"}, "bind_mux": "smux-v1", "transports": []string{"tcp", "ws", "httpupgrade", "http", "grpc", "quic", "xhttp", "mkcp"}},
			{"type": "brook", "without_brook_protocol": true, "tls_record_fragment": true, "tls_fragment": true, "client": true, "server": true, "tcp": true, "udp": true, "tls": true, "udp_over_tcp": true, "udp_over_stream": true, "quic_datagram_limit": 1197, "transports": []string{"tcp", "ws", "wss", "quic"}},
			{"type": "shadowsocksr", "client": true, "server": true, "tcp": true, "udp": true, "authentication": native.SSRProtocols(), "obfuscation": native.SSRObfuscations()},
			{"type": "ssh", "client": true, "server": true, "tcp": true, "udp": true, "udp_extension": "udp-forward@lanboat", "authentication": []string{"password", "publickey", "keyboard-interactive"}, "encrypted_private_keys": true, "key_types": []string{"ed25519", "rsa", "ecdsa-nistp256", "ecdsa-nistp384", "ecdsa-nistp521"}, "host_key_pinning": true},
			{"type": "wireguard", "client": true, "server": true, "tcp": true, "udp": true, "ipv6": true, "tun_device_required": false, "obfuscation": []string{"none", "amneziawg-1.0", "amneziawg-1.5", "amneziawg-2.0", "amneziawg-3.x", "xt_wgobfs"}},
			{"type": "tailscale", "client": true, "server": false, "tcp": true, "udp": true, "icmp_echo": true, "endpoint": true, "auth_key": true, "control_url": true, "exit_node": true, "force_derp": true, "accept_routes": true, "exit_node_allow_lan_access": true, "advertise_routes": true, "advertise_exit_node": true, "advertise_tags": true, "interactive_login": true, "on_demand": true, "taildrop_receive": true, "taildrop_resume": true, "taildrop_cross_account_grants": true, "system_interface": true, "peer_relay": true, "peer_relay_server": true, "peer_relay_client": true, "ssh_server": true, "ssh_session_recording": true, "ssh_unix_forwarding": true, "ssh_chained_delegation": true, "tailnet_lock": true, "tun_device_required": false},
			{"type": "hysteria", "protocols": []string{"udp", "wechat-video", "faketcp"}, "faketcp_platform": "linux", "port_hopping": true, "client": true, "server": true, "tcp": true, "udp": true, "quic": "v1", "obfuscation": []string{"xplus"}, "bbr_version": "1", "congestion_control": []string{"new_reno", "cubic", "bbr"}, "congestion_control_default": "brutal", "bandwidth_congestion_control": "brutal", "loss_compensation": true},
			{"type": "hysteria2", "port_hopping": true, "random_hop_interval": true, "client": true, "server": true, "tcp": true, "udp": true, "quic": "v1", "obfuscation": []string{"salamander", "gecko"}, "bbr_version": "1", "congestion_control": []string{"new_reno", "cubic", "bbr"}, "congestion_control_default": "bbr", "bandwidth_congestion_control": "brutal", "ignore_client_bandwidth": true, "loss_compensation": true},
			{"type": "tuic", "client": true, "server": true, "tcp": true, "udp": true, "versions": []int{4, 5}, "udp_relay_modes": []string{"native", "quic"}, "bbr_version": "1", "congestion_control": []string{"new_reno", "cubic", "bbr"}, "congestion_control_default": "cubic"},
			{"type": "trusttunnel", "client": true, "server": true, "tcp": true, "udp": true, "icmp_echo": true, "tls": true, "http_versions": []int{2, 3}, "authentication": "username/password"},
			{"type": "juicity", "client": true, "server": true, "tcp": true, "udp": true, "quic": "v1", "bbr_version": "1", "congestion_control": []string{"new_reno", "cubic", "bbr"}, "congestion_control_default": "bbr", "certificate_chain_pinning": true},
			{"type": "snell", "client": true, "server": true, "tcp": true, "versions": []int{1, 2, 3, 4, 5}, "udp_over_tcp_versions": []int{3, 4, 5}, "quic_udp": true, "obfuscation": []string{"none", "http", "tls"}, "session_reuse_versions": []int{2, 4, 5}},
			{"type": "tun", "server": true, "platforms": []string{"linux", "windows", "darwin"}, "tcp": true, "udp": true, "icmp_echo": true, "ipv6": true, "dns_modes": []string{"disabled", "native", "hijack"}, "auto_redirect_platforms": []string{"linux"}},
			{"type": "dns", "server": true, "tcp": true, "udp": true, "resolvers": []string{"local", "hosts", "udp", "tcp", "tls", "https", "quic", "h3", "dhcp", "mdns", "fakeip", "masque", "openconnect", "tailscale"}, "policies": true, "bootstrap": true, "cache": true, "network_conditions": []string{"dns_server_address", "dns_search_domain"}, "network_configuration_sources": []string{"local", "dhcp", "masque", "openconnect", "tailscale"}, "preferred_by_sources": []string{"hosts", "openconnect", "tailscale"}},
			{"type": "dns-quic", "server": true, "tls": true, "quic": "v1"},
			{"type": "dns-h3", "server": true, "tls": true, "quic": "v1", "methods": []string{"GET", "POST"}},
		})
	case "run", "client", "server", "check":
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("c", "config.json", "configuration file")
	authStdio := flags.Bool("auth-stdio", false, "OpenConnect JSON authentication prompts on stdout; replies on stdin")
	authBrowser := flags.String("auth-browser", "", "executable to open OpenConnect external-browser login URLs")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *authStdio && *authBrowser != "" {
		return errors.New("choose auth-stdio or auth-browser")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	if args[0] == "check" {
		if *authStdio || *authBrowser != "" {
			return errors.New("auth-stdio/auth-browser requires run,client or server")
		}
		_, err := native.Parse(raw)
		return err
	}
	runtime, err := native.New(ctx, raw, nil)
	if err != nil {
		return err
	}
	defer runtime.Close()
	if *authStdio {
		runtime.SetOpenConnectAuthHandler(openConnectStdio(ctx, os.Stdin, out))
	}
	if *authBrowser != "" {
		runtime.SetOpenConnectAuthHandler(openConnectBrowser(*authBrowser))
	}
	if err := runtime.Start(); err != nil {
		return err
	}
	<-ctx.Done()
	return runtime.Close()
}
