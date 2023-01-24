package phabricator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

type oauthResponse struct {
	Result    User   `json:"result"`
	ErrorCode string `json:"error_code"`
	ErrorInfo string `json:"error_info"`
}

func (d *Config) token(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := d.oauth.Exchange(ctx, code)
	if err != nil {
		return token, fmt.Errorf("d.oauth.Exchange: %w", err)
	}

	if !token.Valid() {
		return token, fmt.Errorf("token is invalid")
	}

	return token, nil
}

func (d *Config) get(ctx context.Context, token *oauth2.Token, dstURL string) ([]byte, error) {
	client := d.oauth.Client(ctx, token)

	//nolint:noctx
	resp, err := client.Get(dstURL)
	if err != nil {
		return nil, fmt.Errorf("client.Get: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bb, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("statusCode is not ok: %d: io.ReadAll: %w", resp.StatusCode, err)
		}

		return nil, fmt.Errorf("statusCode is not ok: %d: body: '%s'", resp.StatusCode, string(bb))
	}

	bb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll: %w", err)
	}

	return bb, nil
}

func (d *Config) unmarshal(body []byte) (User, error) {
	var resp oauthResponse

	err := json.Unmarshal(body, &resp)
	if err != nil {
		return resp.Result, fmt.Errorf("json.Unmarshal: %w", err)
	}

	if resp.ErrorCode != "" {
		return resp.Result, fmt.Errorf("can not find user info: %s", resp.ErrorInfo)
	}

	return resp.Result, nil
}
