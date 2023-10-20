package main

import (
 "bytes"
 "flag"
 "strings"
 "strconv"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
 "os"
 "log"
	"sync"
	"github.com/herumi/bls-eth-go-binary/bls"
 "encoding/hex"
	"encoding/json"
 "io/ioutil"
)

var initBLSOnce sync.Once
func InitBLS() error {
	var err error
	var wg sync.WaitGroup
	initBLSOnce.Do(func() {
		wg.Add(1)
		if err = bls.Init(bls.BLS12_381); err != nil {
			return
		}
		err = bls.SetETHmode(bls.EthModeDraft07)
		wg.Done()
	})
	wg.Wait()
	return err
}

func main() {
	mnemonicPtr := flag.String("m", "", "The mnemonic string. (Required)")
	mnemonicPasswordPtr := flag.String("mp", "", "The mnemonic password. (Default: empty string)")
	keystorePathPtr := flag.String("k", "", "The path to the keystore file. (Required)")
	keystorePasswordPtr := flag.String("p", "", "The keystore password. (Required)")

	flag.Parse()

	// Check if required flags are provided
	if *mnemonicPtr == "" || *keystorePathPtr == "" || *keystorePasswordPtr == "" {
  fmt.Println(`Missing required args, usage: -m "your mnemonic" -k "path/to/keystore" -p "your keystore password"`)
		os.Exit(1)
	}

 mnemonic := *mnemonicPtr
 mnemonicPassword := *mnemonicPasswordPtr
 keystorePath := *keystorePathPtr
 keystorePassword := *keystorePasswordPtr

 InitBLS()

	file, err := ioutil.ReadFile(keystorePath)
	if err != nil {
		panic(err)
	}
	var keystore Keystore
	if err := json.Unmarshal(file, &keystore); err != nil {
		panic(err)
	}

	seed := MnemonicToSeed(normalizePassword(mnemonic), mnemonicPassword)
 masterSk, _ := derive_master_SK(seed)

	fmt.Printf("read HD key path: %s\n", keystore.Path)
	// Remove the "m/" prefix and split the path into its components
	parts := strings.Split(keystore.Path[2:], "/")

	// Start with the master key
	currentSk := masterSk
	for _, part := range parts {
		index, err := strconv.Atoi(part)
		if err != nil {
			log.Fatalf("Invalid path component: %s", part)
		}
		currentSk, _ = derive_child_SK(currentSk, uint32(index))
	}

 decryptedKey := decryptKeystore(keystore, keystorePassword)

 privKeyCheck := bytes.Equal(decryptedKey, currentSk.Bytes())
 if privKeyCheck {
	  fmt.Println("Successfully generated your private key ✓") 
 } else {
	  fmt.Println("Private key does not match.") 
 }

	sk := &bls.SecretKey{}
	if err := sk.SetHexString(hex.EncodeToString(currentSk.Bytes())); err != nil {
		panic(err)
	}
	
 pubKeyCheck := keystore.Pubkey == hex.EncodeToString(sk.GetPublicKey().Serialize())
 if pubKeyCheck {
	  fmt.Println("Successfully generated your public key ✓") 
 } else {
	  fmt.Println("Public key does not match.") 
 }
 
 if privKeyCheck && pubKeyCheck {
	  fmt.Println("Keystore verified to match your mnemonic") 
 } else {
	  fmt.Println("Keystore failed to match your mnemonic") 
 }
}

func MnemonicToSeed(mnemonic string, passphrase string) []byte {
	salt := "mnemonic" + passphrase
	return pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha512.New)
}
