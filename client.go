// Package alfred provides bindings to interact with the alfred daemon via cgo.
package alfred

/*
#cgo CFLAGS: -I${SRCDIR}/alfred -std=gnu99 -D_GNU_SOURCE -fno-strict-aliasing
#cgo LDFLAGS: -pthread
#include <stdlib.h>
#include "binding.h"
*/
import "C"

import (
	"errors"
	"net"
	"strings"
	"sync"
	"unsafe"
)

const (
	DefaultSocketPath = "/var/run/alfred.sock"
	macLen            = 6
)

// ErrClosed is returned when operations are attempted on a closed Client.
var ErrClosed = errors.New("alfred client is closed")

// Mode defines the operating mode used when interacting with the daemon.
type Mode uint8

const (
	ModeSecondary Mode = 0
	ModePrimary   Mode = 1
)

// Option configures a Client during construction.
type Option func(*config)

type config struct {
	socketPath string
	verbose    bool
	ipv4Mode   bool
}

// WithSocketPath overrides the default path to the alfred UNIX domain socket.
func WithSocketPath(path string) Option {
	return func(cfg *config) {
		cfg.socketPath = path
	}
}

// WithVerbose enables verbose logging in the underlying daemon connection.
func WithVerbose(verbose bool) Option {
	return func(cfg *config) {
		cfg.verbose = verbose
	}
}

// WithIPv4Mode toggles IPv4 mode for lookups performed by the daemon.
func WithIPv4Mode(enabled bool) Option {
	return func(cfg *config) {
		cfg.ipv4Mode = enabled
	}
}

// Client provides a threadsafe wrapper around the alfred UNIX socket protocol.
type Client struct {
	mu     sync.Mutex
	c      *C.go_alfred_client
	closed bool
}

// NewClient connects to the alfred daemon using the supplied options.
func NewClient(options ...Option) (*Client, error) {
	cfg := config{
		socketPath: DefaultSocketPath,
		verbose:    false,
		ipv4Mode:   false,
	}

	for _, opt := range options {
		if opt != nil {
			opt(&cfg)
		}
	}

	var cPath *C.char
	if cfg.socketPath != "" {
		cPath = C.CString(cfg.socketPath)
		defer C.free(unsafe.Pointer(cPath))
	}

	client := C.go_alfred_client_new(cPath, boolToCInt(cfg.verbose), boolToCInt(cfg.ipv4Mode))
	if client == nil {
		return nil, errors.New("alfred: failed to create client")
	}

	return &Client{c: client}, nil
}

// Close releases all resources associated with the Client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	C.go_alfred_client_free(c.c)
	c.c = nil
	c.closed = true

	return nil
}

// Record represents a single dataset stored by the alfred daemon.
type Record struct {
	Source  net.HardwareAddr
	Version uint8
	Data    []byte
}

// Request asks the daemon for all records of the given data type.
func (c *Client) Request(dataType uint8) ([]Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrClosed
	}

	var recordsPtr *C.go_alfred_record
	var count C.size_t
	var errStr *C.char

	status := C.go_alfred_client_request(c.c, C.uint8_t(dataType), &recordsPtr, &count, &errStr)
	if errStr != nil {
		defer C.go_alfred_client_free_string(errStr)
	}

	if status != 0 {
		return nil, errors.New(goString(errStr, "alfred request failed"))
	}

	defer C.go_alfred_client_free_records(recordsPtr, count)

	numRecords := int(count)
	result := make([]Record, numRecords)

	if numRecords == 0 {
		return result, nil
	}

	for i := 0; i < numRecords; i++ {
		rec := cRecordAt(recordsPtr, i)

		var macArr [macLen]byte
		C.go_alfred_record_get_source(rec, (*C.uint8_t)(unsafe.Pointer(&macArr[0])))

		mac := make(net.HardwareAddr, macLen)
		copy(mac, macArr[:])

		version := uint8(C.go_alfred_record_get_version(rec))
		dataLen := int(C.go_alfred_record_get_data_len(rec))

		var data []byte
		if dataLen > 0 {
			dataPtr := C.go_alfred_record_get_data(rec)
			if dataPtr != nil {
				data = C.GoBytes(unsafe.Pointer(dataPtr), C.int(dataLen))
			} else {
				data = make([]byte, dataLen)
			}
		}

		result[i] = Record{
			Source:  mac,
			Version: version,
			Data:    data,
		}
	}

	return result, nil
}

// Set publishes the provided payload under the given data type and version.
func (c *Client) Set(dataType uint8, version uint8, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}

	var payloadPtr *C.uint8_t
	if len(payload) > 0 {
		payloadPtr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	}

	var errStr *C.char
	status := C.go_alfred_client_set(c.c, C.uint8_t(dataType), C.uint16_t(version), payloadPtr, C.size_t(len(payload)), &errStr)
	if errStr != nil {
		defer C.go_alfred_client_free_string(errStr)
	}

	if status != 0 {
		return errors.New(goString(errStr, "alfred set failed"))
	}

	return nil
}

// ModeSwitch requests that the daemon switches to the specified operating mode.
func (c *Client) ModeSwitch(mode Mode) error {
	if mode != ModeSecondary && mode != ModePrimary {
		return errors.New("alfred: invalid mode")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}

	var errStr *C.char
	status := C.go_alfred_client_modeswitch(c.c, C.uint8_t(mode), &errStr)
	if errStr != nil {
		defer C.go_alfred_client_free_string(errStr)
	}

	if status != 0 {
		return errors.New(goString(errStr, "alfred mode switch failed"))
	}

	return nil
}

// ChangeInterfaces updates the set of primary interfaces used by the daemon.
func (c *Client) ChangeInterfaces(ifaces ...string) error {
	if len(ifaces) == 0 {
		return errors.New("alfred: at least one interface is required")
	}

	clean := make([]string, len(ifaces))
	for i, iface := range ifaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			return errors.New("alfred: interface names must not be empty")
		}
		clean[i] = iface
	}

	joined := strings.Join(clean, ",")

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}

	cIfaces := C.CString(joined)
	defer C.free(unsafe.Pointer(cIfaces))

	var errStr *C.char
	status := C.go_alfred_client_change_interface(c.c, cIfaces, &errStr)
	if errStr != nil {
		defer C.go_alfred_client_free_string(errStr)
	}

	if status != 0 {
		return errors.New(goString(errStr, "alfred interface change failed"))
	}

	return nil
}

// ChangeBatmanInterface updates the mesh (batman-adv) interface used by the daemon.
func (c *Client) ChangeBatmanInterface(iface string) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return errors.New("alfred: interface name must not be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}

	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(cIface))

	var errStr *C.char
	status := C.go_alfred_client_change_bat_iface(c.c, cIface, &errStr)
	if errStr != nil {
		defer C.go_alfred_client_free_string(errStr)
	}

	if status != 0 {
		return errors.New(goString(errStr, "alfred bat interface change failed"))
	}

	return nil
}

func cRecordAt(base *C.go_alfred_record, idx int) *C.go_alfred_record {
	if base == nil {
		return nil
	}
	offset := uintptr(idx) * unsafe.Sizeof(*base)
	return (*C.go_alfred_record)(unsafe.Pointer(uintptr(unsafe.Pointer(base)) + offset))
}

func boolToCInt(v bool) C.int {
	if v {
		return 1
	}
	return 0
}

func goString(cstr *C.char, fallback string) string {
	if cstr == nil {
		return fallback
	}
	return C.GoString(cstr)
}
