module main

go 1.19

require (
	github.com/gorilla/mux v1.8.0
	github.com/salrashid123/signer/pem v0.0.0-20221027145823-1bbc77226a32
	golang.org/x/net v0.9.0
	util v0.0.0
)

require golang.org/x/text v0.9.0 // indirect

replace util => ./util
