package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	openai "github.com/sashabaranov/go-openai"
)

func TestNewOpenAIClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/gateway/v1/images/generations" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer secret" {
			t.Errorf("Authorization = %q", authorization)
		}
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{
			"data": []map[string]string{{"b64_json": "aW1hZ2U="}},
		})
	}))
	defer server.Close()

	client, err := NewOpenAIClient(LLMConfig{BaseURL: server.URL + "/gateway", APIKey: "secret"}, server.Client())
	if err != nil {
		t.Fatalf("NewOpenAIClient: %v", err)
	}
	response, err := client.CreateImage(context.Background(), openai.ImageRequest{Model: "image", Prompt: "cat", N: 1})
	if err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	if len(response.Data) != 1 || response.Data[0].B64JSON != "aW1hZ2U=" {
		t.Fatalf("response = %+v", response)
	}
}

func TestNewOpenAIClientAcceptsVersionedBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/images/generations" {
			t.Errorf("path = %q", request.URL.Path)
		}
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{"data": []map[string]string{}})
	}))
	defer server.Close()

	client, err := NewOpenAIClient(LLMConfig{BaseURL: server.URL + "/v1/", APIKey: "secret"}, server.Client())
	if err != nil {
		t.Fatalf("NewOpenAIClient: %v", err)
	}
	if _, err := client.CreateImage(context.Background(), openai.ImageRequest{Model: "image", Prompt: "cat", N: 1}); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
}

func TestNewOpenAIClientRejectsInvalidBaseURL(t *testing.T) {
	if _, err := NewOpenAIClient(LLMConfig{BaseURL: "file:///tmp/model", APIKey: "secret"}, nil); err == nil {
		t.Fatal("NewOpenAIClient returned nil error")
	}
}
