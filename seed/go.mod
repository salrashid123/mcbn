module main

go 1.19

require (
	github.com/gorilla/mux v1.8.0
	github.com/salrashid123/mcbn/seed/util v0.0.0
	golang.org/x/net v0.9.0
)

require (
	github.com/canonical/go-sp800.90a-drbg v0.0.0-20210314144037-6eeb1040d6c3 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace (
	github.com/salrashid123/mcbn/seed/util => ./util
)
