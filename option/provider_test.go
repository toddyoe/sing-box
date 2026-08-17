package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

func TestProviderRemotePathConflict(t *testing.T) {
	var options ProviderRemoteOptions
	err := json.Unmarshal([]byte(`{
		"url": "https://example.com/provider.json",
		"path": "provider.json",
		"initial_path": "initial-provider.json"
	}`), &options)
	require.ErrorContains(t, err, "path and initial_path are mutually exclusive")
}

func TestProviderRemoteSinglePath(t *testing.T) {
	for _, content := range []string{
		`{"url":"https://example.com/provider.json","path":"provider.json"}`,
		`{"url":"https://example.com/provider.json","initial_path":"initial-provider.json"}`,
	} {
		var options ProviderRemoteOptions
		require.NoError(t, json.Unmarshal([]byte(content), &options))
	}
}

func TestProviderOverrideTagUnmarshal(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		var options ProviderLocalOptions
		require.NoError(t, json.Unmarshal([]byte(`{
			"path": "provider.txt",
			"override_tag": {
				"additional_prefix": "[JP] ",
				"additional_suffix": " 🇯🇵"
			}
		}`), &options))
		require.NotNil(t, options.OverrideTag)
		require.Equal(t, "[JP]", options.OverrideTag.AdditionalPrefix)
		require.Equal(t, "🇯🇵", options.OverrideTag.AdditionalSuffix)
	})
	t.Run("remote", func(t *testing.T) {
		var options ProviderRemoteOptions
		require.NoError(t, json.Unmarshal([]byte(`{
			"url": "https://example.com/provider.json",
			"override_tag": {
				"additional_prefix": "[JP] ",
				"additional_suffix": " 🇯🇵"
			}
		}`), &options))
		require.NotNil(t, options.OverrideTag)
		require.Equal(t, "[JP]", options.OverrideTag.AdditionalPrefix)
		require.Equal(t, "🇯🇵", options.OverrideTag.AdditionalSuffix)
	})
}

func TestOverrideTagOptionsTrim(t *testing.T) {
	var options OverrideTagOptions
	require.NoError(t, json.Unmarshal([]byte(`{
		"additional_prefix": "  [JP]  ",
		"additional_suffix": "  🇯🇵  "
	}`), &options))
	require.Equal(t, "[JP]", options.AdditionalPrefix)
	require.Equal(t, "🇯🇵", options.AdditionalSuffix)
}

func TestOverrideTagOptionsWhitespaceOnly(t *testing.T) {
	var options OverrideTagOptions
	require.NoError(t, json.Unmarshal([]byte(`{
		"additional_prefix": "   ",
		"additional_suffix": "\t\n"
	}`), &options))
	require.Empty(t, options.AdditionalPrefix)
	require.Empty(t, options.AdditionalSuffix)
	require.Equal(t, "HongKong", options.Apply("HongKong"))
}

func TestOverrideTagOptionsApply(t *testing.T) {
	require.Equal(t, "HongKong", (*OverrideTagOptions)(nil).Apply("HongKong"))
	require.Equal(t, "HongKong", (&OverrideTagOptions{}).Apply("HongKong"))
	require.Equal(t, "[JP]HongKong", (&OverrideTagOptions{AdditionalPrefix: "[JP]"}).Apply("HongKong"))
	require.Equal(t, "HongKong🇯🇵", (&OverrideTagOptions{AdditionalSuffix: "🇯🇵"}).Apply("HongKong"))
	require.Equal(t, "[JP]HongKong🇯🇵", (&OverrideTagOptions{
		AdditionalPrefix: "[JP]",
		AdditionalSuffix: "🇯🇵",
	}).Apply("HongKong"))
	require.Equal(t, "[JP]HongKong", (&OverrideTagOptions{
		AdditionalPrefix: "  [JP]  ",
		AdditionalSuffix: "   ",
	}).Apply("HongKong"))
}

func TestOverrideTagOptionsResolve(t *testing.T) {
	require.Equal(t, "HongKong", (*OverrideTagOptions)(nil).Resolve("HongKong", "sub"))
	require.Equal(t, "HongKong", (&OverrideTagOptions{}).Resolve("HongKong", "sub"))
	require.Equal(t, "[JP]HongKong🇯🇵", (&OverrideTagOptions{
		AdditionalPrefix: "[JP]",
		AdditionalSuffix: "🇯🇵",
	}).Resolve("HongKong", "sub"))
	require.Equal(t, "[sub] [JP]HongKong🇯🇵", (&OverrideTagOptions{
		AdditionalPrefix: "[JP]",
		AdditionalSuffix: "🇯🇵",
		WithProvider:     true,
	}).Resolve("HongKong", "sub"))
	require.Equal(t, "[JP]HongKong", (&OverrideTagOptions{
		AdditionalPrefix: "[JP]",
		WithProvider:     true,
	}).Resolve("HongKong", ""))
}

func TestOverrideTagOptionsWithProviderUnmarshal(t *testing.T) {
	var options OverrideTagOptions
	require.NoError(t, json.Unmarshal([]byte(`{"with_provider": true}`), &options))
	require.True(t, options.WithProvider)
	var unset OverrideTagOptions
	require.NoError(t, json.Unmarshal([]byte(`{}`), &unset))
	require.False(t, unset.WithProvider)
}
