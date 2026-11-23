package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// File writes records as JSON lines to a file, appended to, or to stdout
// ("-"). Each record is flushed as it is written. Reopen opens the file
// again, after logrotate moved it.
type File struct {
	path string

	mu  sync.Mutex
	f   *os.File
	w   *bufio.Writer
	out io.Writer
}

// NewFile opens path, created 0600 when missing; "-" is stdout.
func NewFile(path string) (*File, error) {
	f := &File{path: path}
	if err := f.open(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *File) open() error {
	if f.path == "-" {
		f.out = os.Stdout
		f.w = bufio.NewWriter(os.Stdout)
		return nil
	}
	file, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //#nosec G304 -- the file audit.file.path names
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	f.f, f.out, f.w = file, file, bufio.NewWriter(file)
	return nil
}

// Write writes r as one JSON line.
func (f *File) Write(r Record) {
	fill(&r)
	line, err := json.Marshal(r)
	if err != nil {
		droppedTotal.WithLabelValues("write_failed").Inc()
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err = f.w.Write(append(line, '\n')); err == nil {
		err = f.w.Flush()
	}
	if err != nil {
		droppedTotal.WithLabelValues("write_failed").Inc()
		log.Printf("audit: write %s: %v", f.path, err)
		return
	}
	recordsTotal.WithLabelValues("file").Inc()
}

// Reopen closes the file and opens path again: SIGHUP's, for logrotate.
// stdout is kept.
func (f *File) Reopen() error {
	if f.path == "-" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.w.Flush()
	_ = f.f.Close()
	return f.open()
}

// Close flushes and closes the file.
func (f *File) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.w.Flush()
	if f.f != nil {
		if cerr := f.f.Close(); err == nil {
			err = cerr
		}
	}
	return err
}
