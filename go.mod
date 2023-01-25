module github.com/Megaputer/go_oauth_phabricator/v2

go 1.19

require golang.org/x/oauth2 v0.4.0

require (
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.5.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

retract v2.0.0 // Published accidentally.
