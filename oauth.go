package phabricator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

type oauthResponse struct {
	Result    User   `json:"result"`
	ErrorCode string `json:"error_code"`
	ErrorInfo string `json:"error_info"`
}

func (c *Config) token(code string) (*oauth2.Token, error) {
	token, err := c.oauth.Exchange(context.Background(), code)
	if err != nil {
		return token, fmt.Errorf("oauth config exchange method failed: %w", err)
	}

	if !token.Valid() {
		return token, fmt.Errorf("token is invalid: %w", err)
	}

	return token, nil
}

func (c *Config) body(ctx context.Context, token *oauth2.Token) ([]byte, error) {
	authClient := c.oauth.Client(ctx, token)

	clientInfoURL := c.getClientInfoURL(token.AccessToken).String()

	//nolint:noctx
	authResponse, err := authClient.Get(clientInfoURL)
	if err != nil {
		return nil, fmt.Errorf("can not get auth response: %w", err)
	}

	defer authResponse.Body.Close()

	if authResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("statusCode is not ok: %w", err)
	}

	bb, err := io.ReadAll(authResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll: %w", err)
	}

	return bb, nil
}

func (c *Config) unmarshal(body []byte) (User, error) {
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

func (c *Config) getClientInfoURL(accessToken string) *url.URL {
	u := c.url.JoinPath("api/user.whoami")

	v := url.Values{}

	v.Add("access_token", accessToken)

	u.RawQuery = v.Encode()

	return u
}
