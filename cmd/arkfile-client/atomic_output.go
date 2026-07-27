package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

type atomicOutput struct {
	finalPath string
	tempPath  string
	file      *os.File
	committed bool
}

func createAtomicOutput(finalPath string) (*atomicOutput, error) {
	directory := filepath.Dir(finalPath)
	file, err := os.CreateTemp(directory, ".arkfile-output-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary output file: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, fmt.Errorf("failed to protect temporary output file: %w", err)
	}
	return &atomicOutput{
		finalPath: finalPath,
		tempPath:  file.Name(),
		file:      file,
	}, nil
}

func (output *atomicOutput) abort() {
	if output == nil || output.committed {
		return
	}
	if output.file != nil {
		_ = output.file.Close()
	}
	_ = os.Remove(output.tempPath)
}

func (output *atomicOutput) commit() error {
	if output == nil || output.file == nil {
		return fmt.Errorf("temporary output file is unavailable")
	}
	if err := output.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary output file: %w", err)
	}
	if err := output.file.Close(); err != nil {
		return fmt.Errorf("failed to close temporary output file: %w", err)
	}
	output.file = nil
	if err := os.Rename(output.tempPath, output.finalPath); err != nil {
		return fmt.Errorf("failed to publish completed output file: %w", err)
	}
	output.committed = true
	return nil
}

func writeAtomicOutput(finalPath string, write func(file *os.File) error) error {
	output, err := createAtomicOutput(finalPath)
	if err != nil {
		return err
	}
	defer output.abort()

	if err := write(output.file); err != nil {
		return err
	}
	return output.commit()
}

func interruptContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
