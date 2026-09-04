package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

type PSKManager struct {
	PSK string
}

func NewPSKManager(psk string) *PSKManager {
	return &PSKManager{PSK: psk}
}

func (p *PSKManager) GenerateChallenge(peerPub, myPub []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(p.PSK))
	hasher.Write(peerPub)
	hasher.Write(myPub)
	return hasher.Sum(nil)
}

func (p *PSKManager) VerifyChallenge(challenge, peerPub, myPub []byte) bool {
	expected := p.GenerateChallenge(peerPub, myPub)
	return subtle.ConstantTimeCompare(challenge, expected) == 1
}

func (p *PSKManager) GeneratePSKHash() string {
	if p.PSK == "" {
		return "none"
	}
	hash := sha256.Sum256([]byte(p.PSK))
	return hex.EncodeToString(hash[:8])
}

func (p *PSKManager) IsEnabled() bool {
	return p.PSK != ""
}

func PSKExchange(psk string, peerPub, myPub []byte, isSender bool) (bool, error) {
	if psk == "" {
		return true, nil
	}

	manager := NewPSKManager(psk)
	fmt.Printf("🔐 PSK Hash: %s\n", manager.GeneratePSKHash())

	// Em uma implementação real, enviaríamos o desafio pelo socket
	// Esta é uma versão simplificada para demonstração
	return true, nil
}
