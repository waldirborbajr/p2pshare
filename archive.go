package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ArchiveDir comprime um diretório em um arquivo .tar.gz
func ArchiveDir(dirPath string) (string, error) {
	// Verificar se é diretório
	info, err := os.Stat(dirPath)
	if err != nil {
		return "", fmt.Errorf("erro ao acessar %s: %w", dirPath, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s não é um diretório", dirPath)
	}

	// Criar arquivo temporário
	tmpFile, err := os.CreateTemp("", "p2pshare-archive-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("erro ao criar arquivo temporário: %w", err)
	}
	defer tmpFile.Close()

	// Criar writer gzip
	gzipWriter := gzip.NewWriter(tmpFile)
	defer gzipWriter.Close()

	// Criar writer tar
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Adicionar arquivos ao tar
	baseDir := filepath.Base(dirPath)
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Determinar nome no arquivo
		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			relPath = baseDir
		} else {
			relPath = filepath.Join(baseDir, relPath)
		}
		relPath = filepath.ToSlash(relPath)

		// Criar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("erro ao criar arquivo: %w", err)
	}

	return tmpFile.Name(), nil
}

// ExtractArchive extrai um arquivo .tar.gz para um diretório
func ExtractArchive(archivePath, destDir string) (string, error) {
	// Abrir arquivo
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("erro ao abrir arquivo: %w", err)
	}
	defer file.Close()

	// Criar reader gzip
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("erro ao descomprimir: %w", err)
	}
	defer gzipReader.Close()

	// Criar reader tar
	tarReader := tar.NewReader(gzipReader)

	// Extrair arquivos
	var extractedDir string
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("erro ao ler tar: %w", err)
		}

		// Determinar caminho de destino
		targetPath := filepath.Join(destDir, header.Name)
		if extractedDir == "" {
			extractedDir = filepath.Join(destDir, strings.Split(header.Name, "/")[0])
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			// Criar diretório pai
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return "", err
			}
			// Criar arquivo
			outFile, err := os.Create(targetPath)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return "", err
			}
			outFile.Close()
		}
	}

	if extractedDir == "" {
		return "", fmt.Errorf("nenhum arquivo extraído")
	}

	return extractedDir, nil
}

// IsDirectory verifica se um caminho é um diretório
func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// GetBaseName retorna o nome base do caminho
func GetBaseName(path string) string {
	return filepath.Base(path)
}

// CleanTempFile remove um arquivo temporário
func CleanTempFile(path string) error {
	if path != "" {
		return os.Remove(path)
	}
	return nil
}
