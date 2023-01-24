package phabricator

import (
	"net/url"
)

func (d *Config) userWhoami(accessToken string) *url.URL {
	u := d.url.JoinPath("api/user.whoami")

	vv := url.Values{}

	vv.Set("access_token", accessToken)

	u.RawQuery = vv.Encode()

	return u
}
