package ethrpc

import (
	"io"
	"net/http"
	"net/url"
)

type httpClient interface {
	Post(url string, contentType string, body io.Reader) (*http.Response, error)
}

// WithHttpClient set custom http client
func WithHttpClient(client httpClient) func(rpc *EthRPC) {
	return func(rpc *EthRPC) {
		rpc.client = client
	}
}

func WithHttpProxy(proxy string) func(rpc *EthRPC) {
	return func(rpc *EthRPC) {
		// 代理地址（如 Clash、v2ray 等默认 7890 端口）
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			panic(err)
		}

		// 创建自定义 Transport
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL), // 设置代理
		}

		// 创建 Client
		client := &http.Client{
			Transport: transport, // 使用自定义 Transport
		}
		rpc.client = client
	}
}
