package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	phabricator "github.com/Megaputer/go_oauth_phabricator/v2"
)

// initialize the client.
func initialize() (*phabricator.Config, error) {
	// Get phid and secret from
	// https://phabricator.example.net/oauthserver/query/all/
	phid := "PHID-OASC-..."
	secret := "Application Secret"

	// redirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs
	redirectURL := "https://my.net/auth"

	// phabricatorURL the url of the phabricator server
	// that is the source of OAuth
	phabricatorURL := "https://phabricator.example.net/"

	client, err := phabricator.New(phid, secret, redirectURL, phabricatorURL)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}

	return client, nil
}

func main() {
	ctx := context.Background()

	err := run(ctx)
	if err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	client, err := initialize()
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}

	// AuthCodeURL return url from OAuth with CSRF token
	url := client.AuthCodeURL("csrf_token")

	log.Printf("Open link: %s", url)

	// code will be in the *http.Request.FormValue("code")
	// https://secure.phabricator.com/book/phabcontrib/article/using_oauthserver/
	code := "code_data"

	const (
		countArg = 2
	)

	if len(os.Args) != countArg {
		log.Print("Usage: \n\t$ go run cmd/example/main.go 'code_value'")
	} else {
		code = os.Args[1]
	}

	user, err := client.Authenticate(ctx, code)
	if err != nil {
		return fmt.Errorf("client.Authenticate: %w", err)
	}

	log.Print("User data:")
	log.Printf("\tPHID: '%s'", user.PHID)
	log.Printf("\tUserName: '%s'", user.UserName)
	log.Printf("\tRealName: '%s'", user.RealName)
	log.Printf("\tImage: '%s'", user.Image)
	log.Printf("\tURI: '%s'", user.URI)
	log.Printf("\tRoles: '%s'", user.Roles)
	log.Printf("\tPrimaryEmail: '%s'", user.PrimaryEmail)

	return nil
}
