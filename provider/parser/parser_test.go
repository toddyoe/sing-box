package parser

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

const clashDetourSubscription = `
proxies:
  - name: HongKong
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: Japan
    type: socks5
    server: 127.0.0.1
    port: 1081
    dialer-proxy: HongKong
`

const clashExternalDetourSubscription = `
proxies:
  - name: HongKong
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: Japan
    type: socks5
    server: 127.0.0.1
    port: 1081
    dialer-proxy: external
`

func TestOverrideAnyTLSOptions(t *testing.T) {
	testCases := []struct {
		name                   string
		clientMetadata         *string
		disableReuse           bool
		override               *option.OverrideAnyTLSOptions
		expectedClientMetadata *string
		expectedDisableReuse   bool
	}{
		{
			name: "preserve unset",
		},
		{
			name:                   "preserve value",
			clientMetadata:         common.Ptr("original-client/1.0"),
			disableReuse:           true,
			expectedClientMetadata: common.Ptr("original-client/1.0"),
			expectedDisableReuse:   true,
		},
		{
			name:           "clear",
			clientMetadata: common.Ptr("original-client/1.0"),
			disableReuse:   true,
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr(""),
				DisableReuse:   common.Ptr(false),
			},
			expectedClientMetadata: common.Ptr(""),
		},
		{
			name: "replace",
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr("custom-client/1.0"),
				DisableReuse:   common.Ptr(true),
			},
			expectedClientMetadata: common.Ptr("custom-client/1.0"),
			expectedDisableReuse:   true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbounds := overrideOutbounds([]option.Outbound{{
				Type: C.TypeAnyTLS,
				Options: &option.AnyTLSOutboundOptions{
					ClientMetadata: testCase.clientMetadata,
					DisableReuse:   testCase.disableReuse,
				},
			}}, nil, nil, testCase.override, nil)
			options := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
			require.Equal(t, testCase.expectedClientMetadata, options.ClientMetadata)
			require.Equal(t, testCase.expectedDisableReuse, options.DisableReuse)
		})
	}
}

func TestOverrideDialerInternalDetourKept(t *testing.T) {
	options := overrideDialerOption(option.DialerOptions{
		Detour: "HongKong",
	}, nil, []string{"HongKong"})
	require.Equal(t, "HongKong", options.Detour)
}

func TestOverrideDialerExternalDetourCleared(t *testing.T) {
	options := overrideDialerOption(option.DialerOptions{
		Detour: "external",
	}, nil, []string{"HongKong"})
	require.Empty(t, options.Detour)
}

func TestParseSubscriptionKeepsSourceTagsAndInternalDetour(t *testing.T) {
	outbounds, endpoints, err := ParseSubscription(context.Background(), clashDetourSubscription, nil, nil, nil)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 2)
	require.Equal(t, "HongKong", outbounds[0].Tag)
	require.Equal(t, "Japan", outbounds[1].Tag)
	require.Equal(t, "HongKong", outbounds[1].Options.(*option.SOCKSOutboundOptions).Detour)
}

func TestParseSubscriptionClearsExternalDetour(t *testing.T) {
	outbounds, _, err := ParseSubscription(context.Background(), clashExternalDetourSubscription, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "HongKong", outbounds[0].Tag)
	require.Equal(t, "Japan", outbounds[1].Tag)
	require.Empty(t, outbounds[1].Options.(*option.SOCKSOutboundOptions).Detour)
}
