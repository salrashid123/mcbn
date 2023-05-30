module main

go 1.19

require (
	github.com/gorilla/mux v1.8.0
	golang.org/x/net v0.9.0
	github.com/salrashid123/mcbn/seed/util v0.0.0
)

require golang.org/x/text v0.9.0 // indirect

replace github.com/salrashid123/mcbn/seed/util => ./util
