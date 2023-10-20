package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

type Keystore struct {
	Crypto struct {
		KDF      Module `json:"kdf"`
		Checksum Module `json:"checksum"`
		Cipher   Module `json:"cipher"`
	} `json:"crypto"`
	Pubkey string `json:"pubkey"`
	Path   string `json:"path"`
}

type Module struct {
	Function string                 `json:"function"`
	Params   map[string]interface{} `json:"params"`
	Message  string                 `json:"message"`
}

func normalizePassword(password string) string {
	nfkd := norm.NFKD.String(password)
	var normalized []rune
	for _, r := range nfkd {
		if r < 32 || (r >= 0x80 && r <= 0x9F) || r == 0x7F {
			continue
		}
		normalized = append(normalized, r)
	}
	return string(normalized)
}

func deriveKey(password, salt []byte, kdf Module) []byte {
	switch kdf.Function {
	case "pbkdf2":
		return pbkdf2.Key(password, salt, int(kdf.Params["c"].(float64)), int(kdf.Params["dklen"].(float64)), sha256.New)
	case "scrypt":
		n := int(kdf.Params["n"].(float64))
		r := int(kdf.Params["r"].(float64))
		p := int(kdf.Params["p"].(float64))
		keyLen := int(kdf.Params["dklen"].(float64))
  scr, _ := scrypt.Key(password, salt, n, r, p, keyLen)
  return scr
	default:
		panic("Unsupported KDF")
	}
}

func verifyPassword(decryptionKey []byte, cipherMessage, checksumMessage []byte) bool {
	hashInput := append(decryptionKey[16:32], cipherMessage...)
	hash := sha256.Sum256(hashInput)
	return hex.EncodeToString(hash[:]) == hex.EncodeToString(checksumMessage)
}

func decryptSecret(decryptionKey, cipherText, iv []byte) []byte {
	block, _ := aes.NewCipher(decryptionKey[:16])
	stream := cipher.NewCTR(block, iv)
	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)
	return plainText
}

func decryptKeystore(keystore Keystore, rawPassword string) []byte  {
	normalizedPassword := normalizePassword(rawPassword)
	salt, _ := hex.DecodeString(keystore.Crypto.KDF.Params["salt"].(string))
	decryptionKey := deriveKey([]byte(normalizedPassword), salt, keystore.Crypto.KDF)
	cipherMessage, _ := hex.DecodeString(keystore.Crypto.Cipher.Message)
	checksumMessage, _ := hex.DecodeString(keystore.Crypto.Checksum.Message)

	if !verifyPassword(decryptionKey, cipherMessage, checksumMessage) {
		fmt.Println("Incorrect password!")
  panic("Check keystore password")
	}

	iv, _ := hex.DecodeString(keystore.Crypto.Cipher.Params["iv"].(string))
	secret := decryptSecret(decryptionKey, cipherMessage, iv)
 return secret
}
