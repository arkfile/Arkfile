package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

// errDestinationExists reports that a no-replace publish found an entry
// already present at the destination name.
var errDestinationExists = errors.New("destination already exists")

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

func (output *atomicOutput) closeForPublish() error {
	if output.file == nil {
		return nil
	}
	if err := output.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary output file: %w", err)
	}
	if err := output.file.Close(); err != nil {
		return fmt.Errorf("failed to close temporary output file: %w", err)
	}
	output.file = nil
	return nil
}

// commit publishes the completed output at finalPath, replacing any entry
// already there. Used only for an explicit exact --output path.
func (output *atomicOutput) commit() error {
	if output == nil || output.tempPath == "" {
		return fmt.Errorf("temporary output file is unavailable")
	}
	if err := output.closeForPublish(); err != nil {
		return err
	}
	if err := os.Rename(output.tempPath, output.finalPath); err != nil {
		return fmt.Errorf("failed to publish completed output file: %w", err)
	}
	output.committed = true
	return nil
}

// commitNoReplace publishes the completed output at finalPath only when no
// entry exists there. On errDestinationExists the temporary file is kept so
// the caller can publish it under another name.
func (output *atomicOutput) commitNoReplace(finalPath string) error {
	if output == nil || output.tempPath == "" {
		return fmt.Errorf("temporary output file is unavailable")
	}
	if err := output.closeForPublish(); err != nil {
		return err
	}
	if err := renameNoReplace(output.tempPath, finalPath); err != nil {
		if errors.Is(err, errDestinationExists) {
			return err
		}
		return fmt.Errorf("failed to publish completed output file: %w", err)
	}
	output.finalPath = finalPath
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

// linkNoReplace publishes oldPath at newPath with a hard link, which fails
// when newPath exists, then removes oldPath.
func linkNoReplace(oldPath, newPath string) error {
	if err := os.Link(oldPath, newPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errDestinationExists
		}
		return fmt.Errorf("destination filesystem supports neither no-replace rename nor hard links: %w", err)
	}
	if err := os.Remove(oldPath); err != nil {
		logVerbose("Warning: could not remove temporary output after publish: %v", err)
	}
	return nil
}

func interruptContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
