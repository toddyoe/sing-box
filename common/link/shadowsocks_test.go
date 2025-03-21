package link_test

import (
	"testing"

	"github.com/sagernet/sing-box/common/link"
)

func TestShadowSocks(t *testing.T) {
	runTests(t, link.ParseShadowSocks, TestCases[*link.ShadowSocks]{
		{
			Link: "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1",
			Want: &link.ShadowSocks{
				Address:  "192.168.100.1",
				Port:     8888,
				Ps:       "Example1",
				Method:   "aes-128-gcm",
				Password: "test",
			},
		},
		{
			Link: "ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host=abc.com#Example2",
			Want: &link.ShadowSocks{
				Address:    "192.168.100.1",
				Port:       8888,
				Ps:         "Example2",
				Method:     "rc4-md5",
				Password:   "passwd",
				Plugin:     "obfs-local",
				PluginOpts: "obfs=http;obfs-host=abc.com",
			},
		},
		{
			Link: "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3",
			Want: &link.ShadowSocks{
				Address:  "192.168.100.1",
				Port:     8888,
				Ps:       "Example3",
				Method:   "2022-blake3-aes-256-gcm",
				Password: "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=",
			},
		},
		{
			Link: "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888/?plugin=v2ray-plugin%3Bserver&unsupported-arguments=should-be-ignored#Example3",
			Want: &link.ShadowSocks{
				Address:    "192.168.100.1",
				Port:       8888,
				Ps:         "Example3",
				Method:     "2022-blake3-aes-256-gcm",
				Password:   "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=",
				Plugin:     "v2ray-plugin",
				PluginOpts: "server",
			},
		},
		{
			Link: "ss://aes-128-gcm:password-%E5%AF%86%E7%A0%81@192.168.1.1:443?plugin=v2ray-plugin%3Bserver%3Btls%3Bhost%3Dexample.com#remarks",
			Want: &link.ShadowSocks{
				Ps:         "remarks",
				Method:     "aes-128-gcm",
				Password:   "password-密码",
				Address:    "192.168.1.1",
				Port:       443,
				Plugin:     "v2ray-plugin",
				PluginOpts: "server;tls;host=example.com",
			},
		},
	})
}
