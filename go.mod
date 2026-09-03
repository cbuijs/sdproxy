// File: go.mod
// Description: Go module dependencies for sdproxy.

module sdproxy

go 1.26.0

require (
	github.com/miekg/dns v1.1.73
	github.com/quic-go/quic-go v0.62.0
	golang.org/x/net v0.58.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
