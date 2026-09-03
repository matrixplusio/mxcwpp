package wal

import (
	"os"
	"testing"

	"go.uber.org/zap"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
)

func testLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func TestWriteAndReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, DefaultMaxSize, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// Write 100 records.
	for i := 0; i < 100; i++ {
		record := &grpcProto.EncodedRecord{
			DataType:  3000,
			Timestamp: int64(i),
			Data:      []byte("test-data"),
		}
		if !w.Write(record) {
			t.Fatalf("Write failed at %d", i)
		}
	}

	if !w.HasData() {
		t.Fatal("expected HasData true")
	}

	// Replay.
	var replayed int
	err = w.Replay(50, 0, func(records []*grpcProto.EncodedRecord) error {
		replayed += len(records)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if replayed != 100 {
		t.Fatalf("expected 100 replayed, got %d", replayed)
	}

	// After replay, WAL should be empty.
	if w.HasData() {
		t.Fatal("expected HasData false after replay")
	}

	written, rep, dropped := w.Stats()
	if written != 100 || rep != 100 || dropped != 0 {
		t.Fatalf("unexpected stats: written=%d replayed=%d dropped=%d", written, rep, dropped)
	}
}

func TestMaxSize(t *testing.T) {
	dir := t.TempDir()
	// Very small max size.
	w, err := New(dir, 100, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	var written int
	for i := 0; i < 1000; i++ {
		record := &grpcProto.EncodedRecord{
			DataType:  3000,
			Timestamp: int64(i),
			Data:      []byte("test-data-payload"),
		}
		if w.Write(record) {
			written++
		}
	}

	if written == 1000 {
		t.Fatal("expected some records to be dropped due to size limit")
	}

	_, _, dropped := w.Stats()
	if dropped == 0 {
		t.Fatal("expected dropped > 0")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	// Write with first WAL instance.
	w1, err := New(dir, DefaultMaxSize, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 10; i++ {
		record := &grpcProto.EncodedRecord{
			DataType:  3001,
			Timestamp: int64(i),
			Data:      []byte("persistent-data"),
		}
		w1.Write(record)
	}
	w1.Close()

	// Reopen and replay.
	w2, err := New(dir, DefaultMaxSize, testLogger())
	if err != nil {
		t.Fatalf("New reopen: %v", err)
	}
	defer w2.Close()

	if !w2.HasData() {
		t.Fatal("expected persisted data after reopen")
	}

	var replayed int
	err = w2.Replay(100, 0, func(records []*grpcProto.EncodedRecord) error {
		replayed += len(records)
		for _, r := range records {
			if r.DataType != 3001 {
				t.Errorf("unexpected DataType: %d", r.DataType)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if replayed != 10 {
		t.Fatalf("expected 10 replayed, got %d", replayed)
	}
}

func TestEmptyReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, DefaultMaxSize, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// Replay on empty WAL should be no-op.
	err = w.Replay(100, 0, func(records []*grpcProto.EncodedRecord) error {
		t.Fatal("handler should not be called on empty WAL")
		return nil
	})
	if err != nil {
		t.Fatalf("Replay empty: %v", err)
	}
}

func TestCorruptRecovery(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, DefaultMaxSize, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Write 5 valid records.
	for i := 0; i < 5; i++ {
		record := &grpcProto.EncodedRecord{
			DataType:  3000,
			Timestamp: int64(i),
			Data:      []byte("valid"),
		}
		w.Write(record)
	}
	w.Close()

	// Append garbage to simulate corruption.
	f, _ := os.OpenFile(w.filePath, os.O_APPEND|os.O_WRONLY, 0644)
	_, _ = f.Write([]byte{0xFF, 0xFF}) // partial header
	f.Close()

	// Reopen and replay — should recover valid records.
	w2, err := New(dir, DefaultMaxSize, testLogger())
	if err != nil {
		t.Fatalf("New reopen: %v", err)
	}
	defer w2.Close()

	var replayed int
	err = w2.Replay(100, 0, func(records []*grpcProto.EncodedRecord) error {
		replayed += len(records)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay corrupt: %v", err)
	}

	if replayed != 5 {
		t.Fatalf("expected 5 valid records recovered, got %d", replayed)
	}
}
