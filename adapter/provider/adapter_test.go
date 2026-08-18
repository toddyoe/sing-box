package provider

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func newTestAdapter(providerTag string, override *option.OverrideTagOptions) *Adapter {
	factory := log.NewNOPFactory()
	adapter := NewAdapter(context.Background(), nil, nil, nil, factory, factory.Logger(), providerTag, "local", option.ProviderHealthCheckOptions{}, override)
	return &adapter
}

func socksOutbound(tag string, detour string) option.Outbound {
	return option.Outbound{
		Type: "socks",
		Tag:  tag,
		Options: &option.SOCKSOutboundOptions{
			DialerOptions: option.DialerOptions{Detour: detour},
		},
	}
}

func TestResolveOutboundTagsDefault(t *testing.T) {
	outbounds := []option.Outbound{{Tag: "HongKong"}, {Tag: "Japan"}}
	require.Equal(t, []string{"HongKong", "Japan"}, newTestAdapter("sub", nil).resolveOutboundTags(outbounds))
	require.Equal(t, []string{"HongKong", "Japan"}, newTestAdapter("sub", &option.OverrideTagOptions{}).resolveOutboundTags(outbounds))
	require.Equal(t, []string{"HongKong", "Japan"}, newTestAdapter("sub", &option.OverrideTagOptions{WithProvider: false}).resolveOutboundTags(outbounds))
}

func TestResolveOutboundTagsPrefixSuffix(t *testing.T) {
	outbounds := []option.Outbound{{Tag: "HongKong"}, {Tag: "Japan"}}
	override := &option.OverrideTagOptions{
		AdditionalPrefix: "[JP]",
		AdditionalSuffix: "🇯🇵",
	}
	require.Equal(t, []string{"[JP]HongKong🇯🇵", "[JP]Japan🇯🇵"}, newTestAdapter("sub", override).resolveOutboundTags(outbounds))
}

func TestResolveOutboundTagsWithProvider(t *testing.T) {
	outbounds := []option.Outbound{{Tag: "HongKong"}, {Tag: "Japan"}}
	override := &option.OverrideTagOptions{
		AdditionalPrefix: "[JP]",
		AdditionalSuffix: "🇯🇵",
		WithProvider:     true,
	}
	require.Equal(t, []string{"[sub] [JP]HongKong🇯🇵", "[sub] [JP]Japan🇯🇵"}, newTestAdapter("sub", override).resolveOutboundTags(outbounds))
}

func TestResolveOutboundTagsEmptyAndDuplicate(t *testing.T) {
	a := newTestAdapter("sub", nil)
	require.Equal(t, []string{"0"}, a.resolveOutboundTags([]option.Outbound{{}}))
	require.Equal(t, []string{"A", "A (2)"}, a.resolveOutboundTags([]option.Outbound{{Tag: "A"}, {Tag: "A"}}))

	a = newTestAdapter("sub", &option.OverrideTagOptions{WithProvider: true})
	require.Equal(t, []string{"[sub] 0"}, a.resolveOutboundTags([]option.Outbound{{}}))
	require.Equal(t, []string{"[sub] A", "[sub] A (2)"}, a.resolveOutboundTags([]option.Outbound{{Tag: "A"}, {Tag: "A"}}))
}

func TestResolveEndpointTags(t *testing.T) {
	endpoints := []option.Endpoint{{Tag: "wg"}, {}}
	require.Equal(t, []string{"wg", "endpoint-1"}, newTestAdapter("sub", nil).resolveEndpointTags(endpoints))
	require.Equal(t, []string{"[sub] wg", "[sub] endpoint-1"}, newTestAdapter("sub", &option.OverrideTagOptions{WithProvider: true}).resolveEndpointTags(endpoints))
}

func TestRewriteOutboundInternalDetour(t *testing.T) {
	a := newTestAdapter("sub", &option.OverrideTagOptions{
		AdditionalPrefix: "[JP]",
		WithProvider:     true,
	})
	outbounds := []option.Outbound{
		socksOutbound("HongKong", ""),
		socksOutbound("Japan", "HongKong"),
	}
	tags := a.resolveOutboundTags(outbounds)
	require.Equal(t, []string{"[sub] [JP]HongKong", "[sub] [JP]Japan"}, tags)
	a.rewriteOutboundDetours(outbounds, tags, nil)
	require.Empty(t, outbounds[0].Options.(*option.SOCKSOutboundOptions).Detour)
	require.Equal(t, "[sub] [JP]HongKong", outbounds[1].Options.(*option.SOCKSOutboundOptions).Detour)
	require.Equal(t, "HongKong", outbounds[0].Tag)
	require.Equal(t, "Japan", outbounds[1].Tag)
}

func TestRewriteOutboundUnknownDetourKept(t *testing.T) {
	a := newTestAdapter("sub", &option.OverrideTagOptions{WithProvider: true})
	outbounds := []option.Outbound{socksOutbound("Japan", "external")}
	a.rewriteOutboundDetours(outbounds, a.resolveOutboundTags(outbounds), nil)
	require.Equal(t, "external", outbounds[0].Options.(*option.SOCKSOutboundOptions).Detour)
}

func TestRewriteOutboundDetourIdempotent(t *testing.T) {
	a := newTestAdapter("sub", &option.OverrideTagOptions{WithProvider: true})
	outbounds := []option.Outbound{
		socksOutbound("HongKong", ""),
		socksOutbound("Japan", "HongKong"),
	}
	tags := a.resolveOutboundTags(outbounds)
	a.rewriteOutboundDetours(outbounds, tags, nil)
	a.rewriteOutboundDetours(outbounds, tags, nil)
	require.Equal(t, "[sub] HongKong", outbounds[1].Options.(*option.SOCKSOutboundOptions).Detour)
}
