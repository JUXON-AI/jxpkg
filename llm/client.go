package llm

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	openai "github.com/sashabaranov/go-openai"
)

// LLMConfig 描述单次模型调用使用的连接配置。
type LLMConfig struct {
	// ModelName 是模型服务使用的模型名称。
	ModelName string `json:"model_name" yaml:"model_name"`

	// BaseURL 是 OpenAI 兼容模型服务的基础地址。
	BaseURL string `json:"base_url" yaml:"base_url"`

	// APIKey 是模型服务的访问密钥。
	APIKey string `json:"api_key" yaml:"api_key"`
}

// NewOpenAIClient 使用单次模型调用配置创建 OpenAI 兼容客户端。
func NewOpenAIClient(config LLMConfig, httpClient *http.Client) (*openai.Client, error) {
	baseURL, err := openAIBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	sdkConfig := openai.DefaultConfig(config.APIKey)
	sdkConfig.BaseURL = baseURL
	sdkConfig.HTTPClient = httpClient
	return openai.NewClientWithConfig(sdkConfig), nil
}

func openAIBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("invalid model service base URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("model service base URL must not contain query or fragment")
	}
	if !strings.HasSuffix(parsed.Path, "/v1") {
		parsed.Path += "/v1"
	}
	return parsed.String(), nil
}
