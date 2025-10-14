package alfred

import (
	"net"
	"path/filepath"
	"testing"
)

// TestServerStartStop exercises starting the server and handling inbound connections.
func TestServerStartStop(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "alfred.sock")

	server, err := NewServer(
		WithServerSocketPath(sockPath),
		WithServerInterface("none"),
		WithServerMeshInterface("none"),
		WithServerForce(true),
	)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.Close()

	startOrSkip(t, server)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	conn.Close()

	if err := server.Stop(); err != nil {
		t.Fatalf("stop server: %v", err)
	}
}

// TestServerStopIdempotent ensures Stop can be invoked multiple times safely.
func TestServerStopIdempotent(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "alfred.sock")

	server, err := NewServer(
		WithServerSocketPath(sockPath),
		WithServerInterface("none"),
		WithServerMeshInterface("none"),
		WithServerForce(true),
	)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.Close()

	startOrSkip(t, server)

	if err := server.Stop(); err != nil {
		t.Fatalf("first stop: %v", err)
	}

	if err := server.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}

// TestServerCloseStops verifies Close stops the server and releases resources.
func TestServerCloseStops(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "alfred.sock")

	server, err := NewServer(
		WithServerSocketPath(sockPath),
		WithServerInterface("none"),
		WithServerMeshInterface("none"),
		WithServerForce(true),
	)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	startOrSkip(t, server)

	if err := server.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
}

// startOrSkip begins the server or skips the test if the environment cannot host it.
func startOrSkip(t *testing.T, server *Server) {
	t.Helper()

	if err := server.Start(); err != nil {
		server.Close()
		t.Skipf("skipping server tests: %v", err)
	}
}
