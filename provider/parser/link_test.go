package parser

import (
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestParseV2RayWebsocketEarlyData(t *testing.T) {
	testCases := []struct {
		name                string
		path                string
		maxEarlyData        uint32
		earlyDataHeaderName string
		wantPath            string
		wantMaxEarlyData    uint32
		wantHeaderName      string
	}{
		{
			name:             "basic query",
			path:             "/?ed=2560",
			wantPath:         "/",
			wantMaxEarlyData: 2560,
			wantHeaderName:   "Sec-WebSocket-Protocol",
		},
		{
			name:             "plain path",
			path:             "/ws",
			wantPath:         "/ws",
			wantMaxEarlyData: 0,
			wantHeaderName:   "",
		},
		{
			name:             "explicit max-early-data wins",
			path:             "/?ed=2560",
			maxEarlyData:     1024,
			wantPath:         "/",
			wantMaxEarlyData: 1024,
			wantHeaderName:   "Sec-WebSocket-Protocol",
		},
		{
			name:                "explicit header name wins",
			path:                "/?ed=2560",
			earlyDataHeaderName: "Custom-Header",
			wantPath:            "/",
			wantMaxEarlyData:    2560,
			wantHeaderName:      "Custom-Header",
		},
		{
			name:             "preserve extra query",
			path:             "/ws?foo=bar&ed=2560",
			wantPath:         "/ws?foo=bar",
			wantMaxEarlyData: 2560,
			wantHeaderName:   "Sec-WebSocket-Protocol",
		},
		{
			name:             "invalid ed",
			path:             "/?ed=abc",
			wantPath:         "/?ed=abc",
			wantMaxEarlyData: 0,
			wantHeaderName:   "",
		},
		{
			name:             "zero ed",
			path:             "/?ed=0",
			wantPath:         "/?ed=0",
			wantMaxEarlyData: 0,
			wantHeaderName:   "",
		},
		{
			name:             "empty path",
			path:             "",
			wantPath:         "",
			wantMaxEarlyData: 0,
			wantHeaderName:   "",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path, maxEarlyData, headerName := parseV2RayWebsocketEarlyData(
				testCase.path,
				testCase.maxEarlyData,
				testCase.earlyDataHeaderName,
			)
			require.Equal(t, testCase.wantPath, path)
			require.Equal(t, testCase.wantMaxEarlyData, maxEarlyData)
			require.Equal(t, testCase.wantHeaderName, headerName)
		})
	}
}

func TestParseVLESSLinkWebSocketEarlyData(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=ws&path=%2F%3Fed%3D2560&host=example.com&security=tls&sni=example.com")
	require.NoError(t, err)

	options := outbound.Options.(*option.VLESSOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, "/", options.Transport.WebsocketOptions.Path)
	require.Equal(t, uint32(2560), options.Transport.WebsocketOptions.MaxEarlyData)
	require.Equal(t, "Sec-WebSocket-Protocol", options.Transport.WebsocketOptions.EarlyDataHeaderName)
}

func TestParseVMessLinkSNI(t *testing.T) {
	link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","sni":"example.com"}`))
	outbound, err := ParseSubscriptionLink(link)
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.Equal(t, "192.0.2.1", options.Server)
	require.Equal(t, "example.com", options.TLS.ServerName)
}

func TestParseVMessLinkHostServerNameFallback(t *testing.T) {
	testCases := []struct {
		name       string
		link       string
		serverName string
	}{
		{
			"websocket host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"example.com"}`,
			"example.com",
		},
		{
			"http2 host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"h2","host":"example.com"}`,
			"example.com",
		},
		{
			"explicit sni",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"host.example","sni":"sni.example"}`,
			"sni.example",
		},
		{
			"domain server",
			`{"add":"server.example","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"host.example"}`,
			"server.example",
		},
		{
			"grpc host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"grpc","host":"example.com"}`,
			"192.0.2.1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(testCase.link))
			outbound, err := ParseSubscriptionLink(link)
			require.NoError(t, err)

			options := outbound.Options.(*option.VMessOutboundOptions)
			require.Equal(t, testCase.serverName, options.TLS.ServerName)
		})
	}
}

func TestParseVLESSLinkHostServerNameFallback(t *testing.T) {
	const linkPrefix = "vless://11111111-1111-1111-1111-111111111111@"
	testCases := []struct {
		name       string
		link       string
		serverName string
	}{
		{
			"websocket host",
			"192.0.2.1:443?security=tls&type=ws&host=example.com",
			"example.com",
		},
		{
			"http host",
			"192.0.2.1:443?security=tls&type=http&host=example.com",
			"example.com",
		},
		{
			"explicit sni",
			"192.0.2.1:443?security=tls&type=ws&host=host.example&sni=sni.example",
			"sni.example",
		},
		{
			"domain server",
			"server.example:443?security=tls&type=ws&host=host.example",
			"server.example",
		},
		{
			"reality",
			"192.0.2.1:443?security=reality&type=ws&host=example.com",
			"192.0.2.1",
		},
		{
			"grpc host",
			"192.0.2.1:443?security=tls&type=grpc&host=example.com",
			"192.0.2.1",
		},
		{
			"host with port",
			"192.0.2.1:443?security=tls&type=ws&host=example.com%3A443",
			"192.0.2.1",
		},
		{
			"multiple http hosts",
			"192.0.2.1:443?security=tls&type=http&host=one.example%2Ctwo.example",
			"192.0.2.1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(linkPrefix + testCase.link)
			require.NoError(t, err)

			options := outbound.Options.(*option.VLESSOutboundOptions)
			require.Equal(t, testCase.serverName, options.TLS.ServerName)
		})
	}
}

func TestParseV2RayLinkHostServerNameFallbackRequiresTLS(t *testing.T) {
	vmessLink := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","net":"ws","host":"example.com"}`))
	vmessOutbound, err := ParseSubscriptionLink(vmessLink)
	require.NoError(t, err)
	require.Nil(t, vmessOutbound.Options.(*option.VMessOutboundOptions).TLS)

	vlessOutbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=ws&host=example.com")
	require.NoError(t, err)
	require.Nil(t, vlessOutbound.Options.(*option.VLESSOutboundOptions).TLS)
}

func TestParseHysteria2LinkOptions(t *testing.T) {
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?sni=example.com&pinSHA256=AA:BB&mport=40000-50000")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, []string{"40000:50000"}, []string(options.ServerPorts))
	require.Equal(t, "example.com", options.TLS.ServerName)
	require.Equal(t, "AA:BB", options.TLS.CertificatePinSHA256)
}
