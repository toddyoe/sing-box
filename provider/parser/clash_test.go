package parser

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/stretchr/testify/require"
)

func TestParseClashSnellObfsOptions(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: snell-out
    type: snell
    server: 127.0.0.1
    port: 1080
    psk: password
    version: 5
    udp: true
    obfs-opts:
      mode: http
      host: example.com
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	snellOptions, ok := outbounds[0].Options.(*option.SnellOutboundOptions)
	require.True(t, ok)
	require.Equal(t, 5, snellOptions.Version)
	require.Equal(t, option.NetworkList("tcp\nudp"), snellOptions.Network)
	require.Equal(t, "http", snellOptions.ObfsOptions.ObfsMode)
	require.Equal(t, "example.com", snellOptions.ObfsOptions.ObfsHost)
}

func TestParseClashAnyTLSDisableReuse(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: anytls-out
    type: anytls
    server: 127.0.0.1
    port: 443
    password: password
    disable-reuse: true
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	anyTLSOptions, ok := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
	require.True(t, ok)
	require.True(t, anyTLSOptions.DisableReuse)
}

func TestParseClashWebSocketEarlyData(t *testing.T) {
	testCases := []struct {
		name                string
		yaml                string
		path                string
		maxEarlyData        uint32
		earlyDataHeaderName string
		headers             badoption.HTTPHeader
	}{
		{
			name: "path query",
			yaml: `
proxies:
  - name: vless-ws
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: example.com
    network: ws
    ws-opts:
      path: "/?ed=2560"
      headers:
        host: example.com
`,
			path:                "/",
			maxEarlyData:        2560,
			earlyDataHeaderName: "Sec-WebSocket-Protocol",
			headers:             badoption.HTTPHeader{"host": []string{"example.com"}},
		},
		{
			name: "explicit max-early-data wins",
			yaml: `
proxies:
  - name: vless-ws
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    network: ws
    ws-opts:
      path: "/?ed=2560"
      max-early-data: 1024
      early-data-header-name: Custom-Header
`,
			path:                "/",
			maxEarlyData:        1024,
			earlyDataHeaderName: "Custom-Header",
		},
		{
			name: "preserve extra query",
			yaml: `
proxies:
  - name: vmess-ws
    type: vmess
    server: 127.0.0.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    cipher: auto
    network: ws
    ws-opts:
      path: "/ws?foo=bar&ed=2560"
`,
			path:                "/ws?foo=bar",
			maxEarlyData:        2560,
			earlyDataHeaderName: "Sec-WebSocket-Protocol",
		},
		{
			name: "plain path",
			yaml: `
proxies:
  - name: trojan-ws
    type: trojan
    server: 127.0.0.1
    port: 443
    password: password
    network: ws
    ws-opts:
      path: /ws
`,
			path: "/ws",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbounds, endpoints, err := ParseClashSubscription(context.Background(), testCase.yaml)
			require.NoError(t, err)
			require.Empty(t, endpoints)
			require.Len(t, outbounds, 1)

			var transport *option.V2RayTransportOptions
			switch options := outbounds[0].Options.(type) {
			case *option.VLESSOutboundOptions:
				transport = options.Transport
			case *option.VMessOutboundOptions:
				transport = options.Transport
			case *option.TrojanOutboundOptions:
				transport = options.Transport
			default:
				t.Fatalf("unexpected outbound options %T", outbounds[0].Options)
			}
			require.NotNil(t, transport)
			require.Equal(t, C.V2RayTransportTypeWebsocket, transport.Type)
			require.Equal(t, testCase.path, transport.WebsocketOptions.Path)
			require.Equal(t, testCase.maxEarlyData, transport.WebsocketOptions.MaxEarlyData)
			require.Equal(t, testCase.earlyDataHeaderName, transport.WebsocketOptions.EarlyDataHeaderName)
			require.Equal(t, testCase.headers, transport.WebsocketOptions.Headers)
		})
	}
}

func TestParseClashWebSocketHTTPUpgradeKeepsEarlyDataQuery(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: vless-httpupgrade
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    network: ws
    ws-opts:
      path: "/?ed=2560"
      v2ray-http-upgrade: true
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	options, ok := outbounds[0].Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeHTTPUpgrade, options.Transport.Type)
	require.Equal(t, "/?ed=2560", options.Transport.HTTPUpgradeOptions.Path)
}
