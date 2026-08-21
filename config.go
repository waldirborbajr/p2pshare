package main

import (
	"flag"
	"time"
)

// Config armazena todas as configurações do p2pshare
type Config struct {
	// Timeouts
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration

	// Compressão
	Compress bool

	// PSK (Pre-Shared Key)
	PSK string

	// Logging
	LogJSON bool
	LogLevel string

	// Progresso
	ShowProgress bool

	// Arquivo/Diretório
	SendPath string
	Recv     bool
	Listen   string
	Connect  string
}

// DefaultConfig retorna a configuração padrão
func DefaultConfig() Config {
	return Config{
		HandshakeTimeout: 30 * time.Second,
		ReadTimeout:      60 * time.Second,
		WriteTimeout:     60 * time.Second,
		IdleTimeout:      2 * time.Minute,
		Compress:         false,
		LogJSON:          false,
		LogLevel:         "info",
		ShowProgress:     true,
	}
}

// ParseFlags parseia os flags de linha de comando e retorna uma configuração
func ParseFlags() (Config, error) {
	cfg := DefaultConfig()

	// Flags de timeouts
	flag.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", cfg.HandshakeTimeout, "Timeout para handshake")
	flag.DurationVar(&cfg.ReadTimeout, "read-timeout", cfg.ReadTimeout, "Timeout para leitura")
	flag.DurationVar(&cfg.WriteTimeout, "write-timeout", cfg.WriteTimeout, "Timeout para escrita")
	flag.DurationVar(&cfg.IdleTimeout, "idle-timeout", cfg.IdleTimeout, "Timeout para inatividade")

	// Flags de compressão
	flag.BoolVar(&cfg.Compress, "compress", cfg.Compress, "Comprimir arquivo antes de enviar (usando gzip)")

	// Flags de PSK
	flag.StringVar(&cfg.PSK, "psk", "", "Pre-Shared Key para autenticação adicional")

	// Flags de logging
	flag.BoolVar(&cfg.LogJSON, "log-json", cfg.LogJSON, "Log em formato JSON")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Nível do log (debug, info, warn, error)")

	// Flags de progresso
	flag.BoolVar(&cfg.ShowProgress, "progress", cfg.ShowProgress, "Mostrar barra de progresso")

	// Flags originais
	flag.StringVar(&cfg.SendPath, "send", "", "Arquivo ou diretório para enviar")
	flag.BoolVar(&cfg.Recv, "recv", false, "Receber arquivo")
	flag.StringVar(&cfg.Listen, "listen", "", "Endereço para escutar (ex: :4444)")
	flag.StringVar(&cfg.Connect, "connect", "", "Endereço para conectar (ex: 192.168.1.10:4444)")

	flag.Parse()

	return cfg, nil
}
