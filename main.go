package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Constantes
const (
	ChunkSize   = 1024 * 1024 // 1 MiB
	MaxFrameSize = 128 * 1024 * 1024 // 128 MiB
)

// Variáveis globais
var (
	config Config
	logger *Logger
)

func main() {
	var err error
	config, err = ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erro ao parsear flags: %v\n", err)
		os.Exit(1)
	}

	logger = NewLogger(config.LogJSON, config.LogLevel)

	if err := validateFlags(); err != nil {
		logger.Error("Erro na validação", "error", err)
		os.Exit(1)
	}

	if len(os.Args) > 1 && os.Args[1] == "-ledger-show" {
		showLedger()
		return
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Error("Erro ao gerar chaves", "error", err)
		os.Exit(1)
	}

	logger.Info("Chave pública", "key", fmt.Sprintf("%x", pubKey[:8]))

	if config.Listen != "" {
		listenMode(pubKey, privKey)
		return
	}

	if config.Connect != "" {
		connectMode(pubKey, privKey)
		return
	}

	logger.Error("É necessário especificar -listen ou -connect")
	os.Exit(1)
}

func validateFlags() error {
	if config.Listen == "" && config.Connect == "" {
		return fmt.Errorf("especifique -listen ou -connect")
	}

	if config.SendPath == "" && !config.Recv {
		return fmt.Errorf("especifique -send ou -recv")
	}

	if config.SendPath != "" && config.Recv {
		return fmt.Errorf("não use -send e -recv juntos")
	}

	if config.SendPath != "" {
		if _, err := os.Stat(config.SendPath); os.IsNotExist(err) {
			return fmt.Errorf("arquivo/diretório não encontrado: %s", config.SendPath)
		}
	}

	return nil
}

func listenMode(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) {
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		logger.Error("Erro ao escutar", "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	logger.Info("Escutando", "addr", config.Listen)

	conn, err := listener.Accept()
	if err != nil {
		logger.Error("Erro ao aceitar conexão", "error", err)
		os.Exit(1)
	}
	defer conn.Close()

	logger.Info("Conexão recebida", "from", conn.RemoteAddr().String())

	peerPub, err := authenticate(conn, pubKey, privKey, true)
	if err != nil {
		logger.Error("Falha na autenticação", "error", err)
		os.Exit(1)
	}

	logger.Info("Autenticado", "peer", fmt.Sprintf("%x", peerPub[:8]))

	if config.PSK != "" {
		ok, err := PSKExchange(config.PSK, peerPub, pubKey, true)
		if err != nil || !ok {
			logger.Error("Falha na autenticação PSK", "error", err)
			os.Exit(1)
		}
	}

	if config.SendPath != "" {
		sendFile(conn, config.SendPath, pubKey, privKey)
		return
	}

	if config.Recv {
		receiveFile(conn, pubKey, privKey)
		return
	}

	logger.Info("Aguardando comando do peer...")
}

func connectMode(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) {
	conn, err := net.Dial("tcp", config.Connect)
	if err != nil {
		logger.Error("Erro ao conectar", "error", err)
		os.Exit(1)
	}
	defer conn.Close()

	logger.Info("Conectado", "to", config.Connect)

	peerPub, err := authenticate(conn, pubKey, privKey, false)
	if err != nil {
		logger.Error("Falha na autenticação", "error", err)
		os.Exit(1)
	}

	logger.Info("Autenticado", "peer", fmt.Sprintf("%x", peerPub[:8]))

	if config.PSK != "" {
		ok, err := PSKExchange(config.PSK, peerPub, pubKey, false)
		if err != nil || !ok {
			logger.Error("Falha na autenticação PSK", "error", err)
			os.Exit(1)
		}
	}

	if config.SendPath != "" {
		sendFile(conn, config.SendPath, pubKey, privKey)
		return
	}

	if config.Recv {
		receiveFile(conn, pubKey, privKey)
		return
	}
}

func authenticate(conn net.Conn, pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, isListener bool) (ed25519.PublicKey, error) {
	if _, err := conn.Write(pubKey); err != nil {
		return nil, fmt.Errorf("erro ao enviar chave: %w", err)
	}

	peerPub := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(conn, peerPub); err != nil {
		return nil, fmt.Errorf("erro ao receber chave: %w", err)
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("erro ao gerar desafio: %w", err)
	}

	signature := ed25519.Sign(privKey, challenge)
	if _, err := conn.Write(signature); err != nil {
		return nil, fmt.Errorf("erro ao enviar assinatura: %w", err)
	}

	peerSig := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(conn, peerSig); err != nil {
		return nil, fmt.Errorf("erro ao receber assinatura: %w", err)
	}

	if !ed25519.Verify(peerPub, challenge, peerSig) {
		return nil, fmt.Errorf("falha na verificação da assinatura")
	}

	return peerPub, nil
}

func sendFile(conn net.Conn, path string, pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) {
	logger.Info("Enviando", "path", path)

	sendPath := path
	isArchive := false

	if IsDirectory(path) {
		logger.Info("Diretório detectado, comprimindo...")
		archivePath, err := ArchiveDir(path)
		if err != nil {
			logger.Error("Erro ao comprimir diretório", "error", err)
			os.Exit(1)
		}
		defer CleanTempFile(archivePath)
		sendPath = archivePath
		isArchive = true
	}

	if config.Compress && !isArchive {
		logger.Info("Comprimindo arquivo...")
		compressedPath, err := CompressFile(sendPath)
		if err != nil {
			logger.Error("Erro ao comprimir", "error", err)
			os.Exit(1)
		}
		defer CleanTempFile(compressedPath)
		sendPath = compressedPath
	}

	file, err := os.Open(sendPath)
	if err != nil {
		logger.Error("Erro ao abrir arquivo", "error", err)
		os.Exit(1)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		logger.Error("Erro ao obter info", "error", err)
		os.Exit(1)
	}

	fileSize := info.Size()
	filename := filepath.Base(sendPath)

	logger.Info("Enviando arquivo", "name", filename, "size", fileSize)

	header := fmt.Sprintf("%s|%d\n", filename, fileSize)
	if _, err := conn.Write([]byte(header)); err != nil {
		logger.Error("Erro ao enviar cabeçalho", "error", err)
		os.Exit(1)
	}

	var progress *ProgressBar
	if config.ShowProgress {
		progress = NewProgressBar(fileSize)
	}

	buffer := make([]byte, ChunkSize)
	var sent int64
	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error("Erro ao ler arquivo", "error", err)
			os.Exit(1)
		}

		if _, err := conn.Write(buffer[:n]); err != nil {
			logger.Error("Erro ao enviar dados", "error", err)
			os.Exit(1)
		}

		sent += int64(n)
		if progress != nil {
			progress.SetCurrent(sent)
		}
	}

	if progress != nil {
		progress.Done()
	}

	logger.Info("Envio concluído", "bytes", sent)
	ledgerEntry(sent, filename, "send", pubKey)
}

func receiveFile(conn net.Conn, pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) {
	logger.Info("Recebendo arquivo...")

	reader := bufio.NewReader(conn)
	headerLine, err := reader.ReadString('\n')
	if err != nil {
		logger.Error("Erro ao ler cabeçalho", "error", err)
		os.Exit(1)
	}

	headerParts := strings.Split(strings.TrimSpace(headerLine), "|")
	if len(headerParts) != 2 {
		logger.Error("Cabeçalho inválido")
		os.Exit(1)
	}
	filename := headerParts[0]
	var fileSize int64
	fmt.Sscanf(headerParts[1], "%d", &fileSize)

	logger.Info("Recebendo", "name", filename, "size", fileSize)

	tmpFile, err := os.CreateTemp("", "p2pshare-*.tmp")
	if err != nil {
		logger.Error("Erro ao criar arquivo temporário", "error", err)
		os.Exit(1)
	}
	defer os.Remove(tmpFile.Name())

	var progress *ProgressBar
	if config.ShowProgress {
		progress = NewProgressBar(fileSize)
	}

	buffer := make([]byte, ChunkSize)
	var received int64
	for received < fileSize {
		maxRead := ChunkSize
		if remaining := fileSize - received; remaining < int64(ChunkSize) {
			maxRead = int(remaining)
		}

		n, err := reader.Read(buffer[:maxRead])
		if err != nil {
			logger.Error("Erro ao receber dados", "error", err)
			os.Exit(1)
		}

		if _, err := tmpFile.Write(buffer[:n]); err != nil {
			logger.Error("Erro ao escrever arquivo", "error", err)
			os.Exit(1)
		}

		received += int64(n)
		if progress != nil {
			progress.SetCurrent(received)
		}
	}

	if progress != nil {
		progress.Done()
	}

	if err := tmpFile.Close(); err != nil {
		logger.Error("Erro ao fechar arquivo", "error", err)
		os.Exit(1)
	}

	outputPath := filename
	if strings.HasSuffix(filename, ".tar.gz") || strings.HasSuffix(filename, ".tgz") {
		logger.Info("Arquivo compactado detectado, extraindo...")
		extractedDir, err := ExtractArchive(tmpFile.Name(), ".")
		if err != nil {
			logger.Error("Erro ao extrair arquivo", "error", err)
			os.Exit(1)
		}
		outputPath = extractedDir
	} else if strings.HasSuffix(filename, ".gz") && config.Compress {
		decompressedPath, err := DecompressFile(tmpFile.Name())
		if err != nil {
			logger.Error("Erro ao descomprimir", "error", err)
		} else {
			outputPath = strings.TrimSuffix(filename, ".gz")
			os.Rename(decompressedPath, outputPath)
		}
	} else {
		if err := os.Rename(tmpFile.Name(), outputPath); err != nil {
			logger.Error("Erro ao renomear arquivo", "error", err)
			os.Exit(1)
		}
	}

	logger.Info("Arquivo salvo", "path", outputPath)
	ledgerEntry(received, outputPath, "recv", pubKey)
}

func ledgerEntry(size int64, filename, role string, pubKey ed25519.PublicKey) {
	logger.Info("Ledger registrado", "role", role, "file", filename, "size", size)
}

func showLedger() {
	fmt.Println("📋 Transfer Ledger:")
	fmt.Println("  (Implementação do ledger será adicionada)")
}
