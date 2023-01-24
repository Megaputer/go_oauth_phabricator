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
	PHID         string   `json:"phid"`
	UserName     string   `json:"userName"`
	RealName     string   `json:"realName"`
	Image        string   `json:"image"`
	URI          string   `json:"uri"`
	Roles        []string `json:"roles"`
	PrimaryEmail string   `json:"primaryEmail"`
}

// New сreates a pointer to the structure Config
// that is required to work with OAuth
//
// 'phid' is the client is PHID
// https://phabricator.example.net/oauthserver/query/all/
//
// 'secret' is the application is secret
// available at the push of a button 'Show Application Secret'
//
// 'redirectURL' is the URL to redirect users going through
// the OAuth flow, after the resource owner's URLs.
//
// 'phabricatorURL' the url of the phabricator server
// that is the source of OAuth.
func New(phid string, secret string, redirectURL string, phabricatorURL string) (*Config, error) {
	u, err := url.Parse(phabricatorURL)
	if err != nil {
		return nil, fmt.Errorf("url.Parse: %w", err)
	}

	authURL := u.JoinPath("/oauthserver/auth/").String()
	tokenURL := u.JoinPath("/oauthserver/token/").String()

	e := oauth2.Endpoint{
		AuthURL:  authURL,
		TokenURL: tokenURL,
	}

	o := &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     phid,
		ClientSecret: secret,
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
func (d *Config) Authenticate(ctx context.Context, code string) (User, error) {
	var user User

	token, err := d.token(ctx, code)
	if err != nil {
		return user, fmt.Errorf("d.token: %w", err)
	}

	whoamiURL := d.userWhoami(token.AccessToken).String()

	bb, err := d.get(ctx, token, whoamiURL)
	if err != nil {
		return user, fmt.Errorf("d.body: %w", err)
	}

	user, err = d.unmarshal(bb)
	if err != nil {
		return user, fmt.Errorf("d.unmarshal: %w", err)
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
func (d *Config) AuthCodeURL(state string) string {
	return d.oauth.AuthCodeURL(state)
}
