// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

// retirementTUN models an Android descriptor: closing it unblocks both an
// in-flight Write and Read, and the interrupted Read reports EOF.
type retirementTUN struct {
	closed chan struct{}
	events chan tun.Event

	writeStarted chan struct{}
	readStarted  chan struct{}
	readExited   chan struct{}
	packets      chan []byte

	closeOnce        sync.Once
	writeStartedOnce sync.Once
	readStartedOnce  sync.Once
	readExitedOnce   sync.Once
}

func newRetirementTUN() *retirementTUN {
	return &retirementTUN{
		closed:       make(chan struct{}),
		events:       make(chan tun.Event),
		writeStarted: make(chan struct{}),
		readStarted:  make(chan struct{}),
		readExited:   make(chan struct{}),
		packets:      make(chan []byte, 1),
	}
}

func (d *retirementTUN) File() *os.File { return nil }

func (d *retirementTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	d.readStartedOnce.Do(func() { close(d.readStarted) })
	select {
	case <-d.closed:
		d.readExitedOnce.Do(func() { close(d.readExited) })
		return 0, io.EOF
	case packet := <-d.packets:
		if len(packets) == 0 || tun.ReadPacketSpacing+len(packet) > len(slab) {
			return 0, tun.ErrTooManySegments
		}
		offset := tun.ReadPacketSpacing
		copy(slab[offset:], packet)
		packets[0] = tun.ReadPacket{Offset: offset, Size: len(packet)}
		return 1, nil
	}
}

func (d *retirementTUN) Write([][]byte, int) (int, error) {
	d.writeStartedOnce.Do(func() { close(d.writeStarted) })
	<-d.closed
	return 0, io.ErrClosedPipe
}

func (*retirementTUN) MTU() (int, error)          { return 1280, nil }
func (*retirementTUN) Name() (string, error)      { return "retirement-test", nil }
func (d *retirementTUN) Events() <-chan tun.Event { return d.events }
func (d *retirementTUN) BatchSize() int           { return 1 }

func (d *retirementTUN) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		close(d.events)
	})
	return nil
}

func awaitTUNSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func awaitWriteResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("blocked multiTUN.Write was not released")
		return nil
	}
}

func startPendingRead(d *multiTUN) <-chan error {
	result := make(chan error, 1)
	go func() {
		_, err := d.Read(make([]byte, 128), make([]tun.ReadPacket, 1))
		result <- err
	}()
	return result
}

func awaitReadResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("pending multiTUN.Read was not released")
		return nil
	}
}

func installTUNCloseCleanup(t *testing.T, d *multiTUN) func() error {
	t.Helper()
	var once sync.Once
	var err error
	closeDevice := func() error {
		once.Do(func() { err = d.Close() })
		return err
	}
	t.Cleanup(func() { _ = closeDevice() })
	return closeDevice
}

func waitForReplacementPacket(t *testing.T, d *multiTUN, want []byte) {
	t.Helper()
	type readResult struct {
		packet []byte
		err    error
	}
	result := make(chan readResult, 1)
	go func() {
		for {
			slab := make([]byte, 128)
			packets := make([]tun.ReadPacket, 1)
			n, err := d.Read(slab, packets)
			if err != nil {
				result <- readResult{err: err}
				return
			}
			if n > 0 {
				packet := packets[0]
				result <- readResult{packet: append([]byte(nil), slab[packet.Offset:packet.Offset+packet.Size]...)}
				return
			}
		}
	}()

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("Read returned an error after the retired TUN's expected EOF: %v", got.err)
		}
		if string(got.packet) != string(want) {
			t.Fatalf("Read got packet %q, want %q", got.packet, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("multiTUN reader did not resume on the replacement TUN")
	}
}

func TestMultiTUNReplacementUnblocksWriteAndContinuesAfterRetiredReadEOF(t *testing.T) {
	d := newTUNDevices()
	if !d.Up() {
		t.Fatal("new multiTUN did not transition up")
	}
	installTUNCloseCleanup(t, d)

	old := newRetirementTUN()
	d.add(old)
	oldRead := startPendingRead(d)
	awaitTUNSignal(t, old.readStarted, "first TUN Read")

	writeResult := make(chan error, 1)
	go func() {
		_, err := d.Write([][]byte{[]byte("blocked packet")}, 0)
		writeResult <- err
	}()
	awaitTUNSignal(t, old.writeStarted, "blocked physical TUN.Write")

	replacement := newRetirementTUN()
	replacement.packets <- []byte("from replacement")
	d.add(replacement)

	if err := awaitWriteResult(t, writeResult); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write error = %v, want %v after descriptor close", err, io.ErrClosedPipe)
	}
	if err := awaitReadResult(t, oldRead); err != nil {
		t.Fatalf("Read error after retired descriptor returned EOF = %v, want nil", err)
	}
	awaitTUNSignal(t, old.readExited, "retired TUN Read to exit")
	waitForReplacementPacket(t, d, []byte("from replacement"))
}

func TestMultiTUNShutdownUnblocksWriteAndRetiredRead(t *testing.T) {
	d := newTUNDevices()
	if !d.Up() {
		t.Fatal("new multiTUN did not transition up")
	}
	closeDevice := installTUNCloseCleanup(t, d)

	dev := newRetirementTUN()
	d.add(dev)
	readResult := startPendingRead(d)
	awaitTUNSignal(t, dev.readStarted, "TUN Read")

	writeResult := make(chan error, 1)
	go func() {
		_, err := d.Write([][]byte{[]byte("blocked packet")}, 0)
		writeResult <- err
	}()
	awaitTUNSignal(t, dev.writeStarted, "blocked physical TUN.Write")

	shutdownDone := make(chan struct{})
	go func() {
		d.Shutdown()
		close(shutdownDone)
	}()
	awaitTUNSignal(t, shutdownDone, "multiTUN shutdown")
	if err := awaitWriteResult(t, writeResult); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write error = %v, want %v after shutdown closes descriptor", err, io.ErrClosedPipe)
	}
	if err := awaitReadResult(t, readResult); err != nil {
		t.Fatalf("Read error after shutdown retired the descriptor = %v, want nil", err)
	}
	awaitTUNSignal(t, dev.readExited, "retired TUN Read to exit")

	if err := closeDevice(); err != nil {
		t.Fatalf("multiTUN.Close() = %v", err)
	}
}
