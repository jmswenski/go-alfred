package alfred

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	testAlfredVersion          = 0
	testAlfredRequest          = 2
	testAlfredPushData         = 0
	testAlfredModeSwitch       = 5
	testAlfredChangeIface      = 6
	testAlfredChangeBatIf      = 7
	testModePrimary       Mode = 1
)

// TestClientRequest verifies that Request parses a push_data response into a Record.
func TestClientRequest(t *testing.T) {
	const dataType = 42
	payload := []byte("hello")
	mac := [6]byte{0x02, 0x42, 0x42, 0x42, 0x42, 0x42}
	recordVersion := uint8(7)

	sock, wait := withUnixServer(t, func(conn io.ReadWriteCloser) error {
		buf := make([]byte, 7)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("read request: %w", err)
		}

		if buf[0] != testAlfredRequest {
			return fmt.Errorf("unexpected request type %d", buf[0])
		}
		if buf[1] != testAlfredVersion {
			return fmt.Errorf("unexpected request version %d", buf[1])
		}
		if binary.BigEndian.Uint16(buf[2:4]) != 3 {
			return fmt.Errorf("unexpected request length %d", binary.BigEndian.Uint16(buf[2:4]))
		}
		if buf[4] != dataType {
			return fmt.Errorf("unexpected data type %d", buf[4])
		}

		response := buildPushDataResponse(buf[5:7], dataType, mac, recordVersion, payload)
		if _, err := conn.Write(response); err != nil {
			return fmt.Errorf("write response: %w", err)
		}

		return nil
	})
	defer wait()

	client, err := NewClient(WithSocketPath(sock))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	records, err := client.Request(dataType)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if !bytes.Equal(rec.Source, mac[:]) {
		t.Fatalf("unexpected mac %v", rec.Source)
	}
	if rec.Version != recordVersion {
		t.Fatalf("unexpected version %d", rec.Version)
	}
	if !bytes.Equal(rec.Data, payload) {
		t.Fatalf("unexpected data %q", rec.Data)
	}
}

// TestClientSet ensures Set emits the expected push_data payload over the socket.
func TestClientSet(t *testing.T) {
	const dataType = 99
	const version = 3
	payload := []byte{0xde, 0xad, 0xbe, 0xef}

	sock, wait := withUnixServer(t, func(conn io.ReadWriteCloser) error {
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return fmt.Errorf("read header: %w", err)
		}

		if header[0] != testAlfredPushData {
			return fmt.Errorf("unexpected type %d", header[0])
		}
		if header[1] != testAlfredVersion {
			return fmt.Errorf("unexpected version %d", header[1])
		}

		tlvLen := binary.BigEndian.Uint16(header[2:4])
		body := make([]byte, tlvLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		if binary.BigEndian.Uint16(body[2:4]) != 0 {
			return fmt.Errorf("expected seqno 0")
		}
		if !bytes.Equal(body[4:10], make([]byte, 6)) {
			return fmt.Errorf("expected zeroed mac, got %v", body[4:10])
		}
		if body[10] != dataType {
			return fmt.Errorf("unexpected data type %d", body[10])
		}
		if body[11] != version {
			return fmt.Errorf("unexpected version %d", body[11])
		}
		dataLen := int(binary.BigEndian.Uint16(body[12:14]))
		if dataLen != len(payload) {
			return fmt.Errorf("unexpected payload length %d", dataLen)
		}
		if !bytes.Equal(body[14:], payload) {
			return fmt.Errorf("unexpected payload %x", body[14:])
		}
		return nil
	})
	defer wait()

	client, err := NewClient(WithSocketPath(sock))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.Set(dataType, version, payload); err != nil {
		t.Fatalf("set: %v", err)
	}
}

// TestClientModeSwitch confirms ModeSwitch transmits the primary-mode request.
func TestClientModeSwitch(t *testing.T) {
	sock, wait := withUnixServer(t, func(conn io.ReadWriteCloser) error {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("read modeswitch: %w", err)
		}
		if buf[0] != testAlfredModeSwitch {
			return fmt.Errorf("unexpected type %d", buf[0])
		}
		if buf[4] != byte(testModePrimary) {
			return fmt.Errorf("unexpected mode %d", buf[4])
		}
		return nil
	})
	defer wait()

	client, err := NewClient(WithSocketPath(sock))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.ModeSwitch(ModePrimary); err != nil {
		t.Fatalf("mode switch: %v", err)
	}
}

// TestClientChangeInterfaces asserts that ChangeInterfaces sends the joined list.
func TestClientChangeInterfaces(t *testing.T) {
	expected := "eth0,wlan0"

	sock, wait := withUnixServer(t, func(conn io.ReadWriteCloser) error {
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return fmt.Errorf("read header: %w", err)
		}
		if header[0] != testAlfredChangeIface {
			return fmt.Errorf("unexpected type %d", header[0])
		}

		tlvLen := binary.BigEndian.Uint16(header[2:4])
		body := make([]byte, tlvLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		got := string(bytes.TrimRight(body, "\x00"))
		if got != expected {
			return fmt.Errorf("unexpected iface string %q", got)
		}
		return nil
	})
	defer wait()

	client, err := NewClient(WithSocketPath(sock))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.ChangeInterfaces("eth0", "wlan0"); err != nil {
		t.Fatalf("change interfaces: %v", err)
	}
}

// TestClientChangeBatmanInterface checks that ChangeBatmanInterface passes the value through.
func TestClientChangeBatmanInterface(t *testing.T) {
	expected := "bat0"

	sock, wait := withUnixServer(t, func(conn io.ReadWriteCloser) error {
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return fmt.Errorf("read header: %w", err)
		}
		if header[0] != testAlfredChangeBatIf {
			return fmt.Errorf("unexpected type %d", header[0])
		}

		tlvLen := binary.BigEndian.Uint16(header[2:4])
		body := make([]byte, tlvLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		got := string(bytes.TrimRight(body, "\x00"))
		if got != expected {
			return fmt.Errorf("unexpected bat iface %q", got)
		}
		return nil
	})
	defer wait()

	client, err := NewClient(WithSocketPath(sock))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.ChangeBatmanInterface(expected); err != nil {
		t.Fatalf("change bat iface: %v", err)
	}
}

// TestClientChangeInterfacesErrors validates input validation on ChangeInterfaces.
func TestClientChangeInterfacesErrors(t *testing.T) {
	client, err := NewClient(WithSocketPath(dummySocketPath(t)))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.ChangeInterfaces(); err == nil {
		t.Fatalf("expected error for empty interface list")
	}
}

// TestClientChangeBatmanInterfaceErrors validates input validation on ChangeBatmanInterface.
func TestClientChangeBatmanInterfaceErrors(t *testing.T) {
	client, err := NewClient(WithSocketPath(dummySocketPath(t)))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.ChangeBatmanInterface(" "); err == nil {
		t.Fatalf("expected error for empty interface name")
	}
}

// TestClientModeSwitchInvalid ensures invalid modes are rejected before hitting cgo.
func TestClientModeSwitchInvalid(t *testing.T) {
	client, err := NewClient(WithSocketPath(dummySocketPath(t)))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.ModeSwitch(Mode(99)); err == nil {
		t.Fatalf("expected invalid mode error")
	}
}

// withUnixServer launches an in-memory UNIX socket pair to emulate alfred.
func withUnixServer(t *testing.T, handler func(io.ReadWriteCloser) error) (string, func()) {
	t.Helper()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}

	clientFD, serverFD := fds[0], fds[1]
	setTestSocket(clientFD)

	conn := os.NewFile(uintptr(serverFD), "alfred-server")
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)
		defer conn.Close()

		if err := handler(conn); err != nil {
			errCh <- err
		}
	}()

	cleanup := func() {
		if err, ok := <-errCh; ok && err != nil {
			t.Fatalf("server: %v", err)
		}
	}

	return ":test:", cleanup
}

// dummySocketPath creates an unused socket path for negative tests.
func dummySocketPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "does-not-exist.sock")
}

// buildPushDataResponse fabricates a push_data frame matching alfred's layout.
func buildPushDataResponse(txID []byte, dataType uint8, mac [6]byte, version uint8, payload []byte) []byte {
	total := 4 + 4 + 6 + 4 + len(payload)
	buf := make([]byte, total)

	buf[0] = testAlfredPushData
	buf[1] = testAlfredVersion
	binary.BigEndian.PutUint16(buf[2:], uint16(total-4))

	copy(buf[4:6], txID)
	binary.BigEndian.PutUint16(buf[6:8], 0)

	copy(buf[8:14], mac[:])
	buf[14] = dataType
	buf[15] = version
	binary.BigEndian.PutUint16(buf[16:18], uint16(len(payload)))
	copy(buf[18:], payload)

	return buf
}
