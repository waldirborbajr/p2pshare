package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CompressFile comprime um arquivo usando gzip
func CompressFile(inputPath string) (string, error) {
	outputPath := inputPath + ".gz"
	tmpFile, err := os.CreateTemp(filepath.Dir(inputPath), "p2pshare-compress-*.gz")
	if err != nil {
		return "", fmt.Errorf("erro ao criar arquivo temporário: %w", err)
	}
	defer tmpFile.Close()

	inputFile, err := os.Open(inputPath)
	if err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("erro ao abrir arquivo: %w", err)
	}
	defer inputFile.Close()

	gzipWriter := gzip.NewWriter(tmpFile)
	defer gzipWriter.Close()

	if _, err := io.Copy(gzipWriter, inputFile); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("erro ao comprimir: %w", err)
	}

	if err := gzipWriter.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	if err := os.Rename(tmpFile.Name(), outputPath); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return outputPath, nil
}

// DecompressFile descomprime um arquivo .gz
func DecompressFile(inputPath string) (string, error) {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return "", fmt.Errorf("erro ao abrir arquivo: %w", err)
	}
	defer inputFile.Close()

	gzipReader, err := gzip.NewReader(inputFile)
	if err != nil {
		return "", fmt.Errorf("erro ao criar reader gzip: %w", err)
	}
	defer gzipReader.Close()

	outputPath := strings.TrimSuffix(inputPath, ".gz")
	if outputPath == inputPath {
		outputPath = inputPath + ".decompressed"
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("erro ao criar arquivo: %w", err)
	}
	defer outputFile.Close()

	if _, err := io.Copy(outputFile, gzipReader); err != nil {
		os.Remove(outputPath)
		return "", fmt.Errorf("erro ao descomprimir: %w", err)
	}

	return outputPath, nil
}

// IsCompressed verifica se o arquivo parece ser um .gz
func IsCompressed(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".gz" || ext == ".gzip"
}
