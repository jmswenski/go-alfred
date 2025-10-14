# go-alfred

Go bindings for the bundled [alfred](./alfred) C library. The package uses cgo to talk to the alfred daemon over its UNIX socket, providing idiomatic Go helpers to request and publish data types.

## Building

1. Ensure the submodule is checked out and current:
   ```bash
   git submodule update --init --recursive
   ```
2. Build the native dependency once to generate headers/binaries:
   ```bash
   (cd ./alfred && make)
   ```
3. Build the Go bindings (the `GOCACHE` override confines build artifacts to the repo):
   ```bash
   GOCACHE=$(pwd)/.gocache go build ./...
   ```

## Running

The repository ships with demo binaries under `cmd/`.

### Start the server

```bash
go build -o cmd/demo-server/demo-server ./cmd/demo-server
./cmd/demo-server/demo-server --socket ./tmp/alfred.sock
```

- If you want to bind to `/var/run/alfred.sock`, run the binary with elevated permissions.
- The server auto-detects the first active non-loopback interface; override with `--iface <name>` as needed.

### Publish and read data

```bash
go build -o cmd/demo-client/demo-client ./cmd/demo-client

# Publish a record under type 200, version 1
./cmd/demo-client/demo-client --socket ./tmp/alfred.sock --type 200 --payload "hello from demo"

# Request all records for type 200
./cmd/demo-client/demo-client --socket ./tmp/alfred.sock --type 200
```

Omit the `--socket` flag when working against the system daemon at `/var/run/alfred.sock`.

## Example

```go
package main

import (
    "fmt"
    "log"

    "go-alfred"
)

func main() {
    client, err := alfred.NewClient()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    records, err := client.Request(64)
    if err != nil {
        log.Fatal(err)
    }

    for _, rec := range records {
        fmt.Printf("%s: %q\n", rec.Source, rec.Data)
    }
}
```

## Notes

* Ensure the `alfred` submodule is initialised (`git submodule update --init --recursive`) and built with `make` so the headers and daemon binary exist locally.
* The daemon must be running and reachable through `alfred`'s UNIX socket (default: `/var/run/alfred.sock`).
* Only client-side operations are exposed (requesting and pushing data). Additional operations can be added following the same pattern if required.
* The upstream `alfred/batadv_query*.c` sources—which query the kernel's batman-adv subsystem via libnl/libcap—are replaced in this module with `batadv_stub.c`. The stub keeps the MAC/IPv6 helpers used by `netsock.c`/`recv.c` but turns all mesh-specific calls (interface validation, translation-table lookups, TQ scoring, etc.) into no-ops so the bindings build everywhere without extra system dependencies. As a result, batman-adv integration is effectively disabled: mesh interfaces cannot be auto-validated (you must pass `--force` when running the bundled server with a real mesh iface), and no TQ-based server selection or address translation is performed.

## Testing

Run the suite after building the native dependency:

```bash
GOCACHE=$(pwd)/.gocache go test ./...
```
