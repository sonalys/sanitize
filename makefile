.SILENT:

lint:
	go tool -modfile=.tools/golangci-lint.mod golangci-lint run

test:
	go tool -modfile=.tools/gotesttools.mod gotestsum --format testname -- -count 1 -v ./...