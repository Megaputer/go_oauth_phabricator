// Package phabricator provides methods for using OAuth2 to access Phabricator.
package phabricator

import (
	"context"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"
)

// Config for OAuth.
type Config struct {
	url   *url.URL
	oauth *oauth2.Config
}

// User is the result of the function
// JSON looks like:
//
//	{
//	 "phid": "PHID-USER-...",
//	 "userName": "...",
//	 "realName": "...",
//	 "image": phabricator_user_picture,
//	 "uri": phabricator_user_url,
//	 "roles": ["admin", "verified", "approved", "activated"],
//	 "primaryEmail": email
//	}
type User struct {
	Phid         string   `json:"phid"`
	UserName     string   `json:"userName"`
	RealName     string   `json:"realName"`
	Image        string   `json:"image"`
	URI          string   `json:"uri"`
	Roles        []string `json:"roles"`
	PrimaryEmail string   `json:"primaryEmail"`
}

// ClientConfig сreates a pointer to the structure Config
// that is required to work with OAuth
//
// clientID is the application's PHID
// https://example.phabricator.com/oauthserver/query/all/
//
// clientSecret is the application's secret.
//
// redirectURL is the URL to redirect users going through
// the OAuth flow, after the resource owner's URLs.
//
// phabricatorURL the url of the phabricator server
// that is the source of OAuth.
func ClientConfig(clientID string, clientSecret string, redirectURL string, phabricatorURL string) (*Config, error) {
	u, err := url.Parse(phabricatorURL)
	if err != nil {
		return nil, fmt.Errorf("url.Parse: %w", err)
	}

	authURL := u.JoinPath("oauthserver/auth").String()
	tokenURL := u.JoinPath("oauthserver/token").String()

	e := oauth2.Endpoint{
		AuthURL:  authURL,
		TokenURL: tokenURL,
	}

	o := &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     e,
	}

	c := &Config{
		url:   u,
		oauth: o,
	}

	return c, nil
}

// Authenticate returns the structure of the User, by code.
// The code will be in the *http.Request.FormValue("code")
// https://secure.phabricator.com/book/phabcontrib/article/using_oauthserver/
func (c *Config) Authenticate(ctx context.Context, code string) (User, error) {
	var user User

	token, err := c.token(code)
	if err != nil {
		return user, fmt.Errorf("token: %w", err)
	}

	body, err := c.body(ctx, token)
	if err != nil {
		return user, fmt.Errorf("body: %w", err)
	}

	user, err = c.unmarshal(body)
	if err != nil {
		return user, fmt.Errorf("unmarshal: %w", err)
	}

	return user, nil
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-empty string and validate that it matches
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
func (c *Config) AuthCodeURL(state string) string {
	return c.oauth.AuthCodeURL(state)
}
