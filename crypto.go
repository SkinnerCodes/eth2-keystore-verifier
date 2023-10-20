package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"golang.org/x/crypto/hkdf"
)

var (
	R, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
)

func flip_bits(in []byte) []byte {
 inverse := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		inverse[i] = ^in[i]
	}
 return inverse
}

// 0. PRK = HKDF-Extract(salt, IKM)
// 1. OKM = HKDF-Expand(PRK, "" , L)
// 2. lamport_SK = bytes_split(OKM, K)
// 3. return lamport_SK
func IKM_to_lamport_SK(IKM []byte, salt []byte) ([][]byte, error) {
 K := 32
 L := K * 255
	PRK := hkdf.Extract(sha256.New, IKM, salt)
	okmReader := hkdf.Expand(sha256.New, PRK, nil)

 lamport_SK := make([][]byte, L/K)
 for i := 0; i < L/K; i++ {
     chunk := make([]byte, K)
     _, err := io.ReadFull(okmReader, chunk)
     if err != nil {
         return nil, err
     }
     lamport_SK[i] = chunk
 }

 return lamport_SK, nil
}

// 0. salt = I2OSP(index, 4)
// 1. IKM = I2OSP(parent_SK, 32)
// 2. lamport_0 = IKM_to_lamport_SK(IKM, salt)
// 3. not_IKM = flip_bits(IKM)
// 4. lamport_1 = IKM_to_lamport_SK(not_IKM, salt)
// 5. lamport_PK = ""
// 6. for i  in 1, .., 255
//        lamport_PK = lamport_PK | SHA256(lamport_0[i])
// 7. for i  in 1, .., 255
//        lamport_PK = lamport_PK | SHA256(lamport_1[i])
// 8. compressed_lamport_PK = SHA256(lamport_PK)
// 9. return compressed_lamport_PK_
func parent_SK_to_lamport_PK(parent_SK *big.Int, index uint32) ([]byte, error) {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, index)

	IKM := make([]byte, 32)
 //FillBytes sets input to the absolute value of x, storing it as a zero-extended big-endian byte slice, and returns buf.
	parent_SK.FillBytes(IKM)

	lamport_0, err := IKM_to_lamport_SK(IKM, salt)
	if err != nil {
		return nil, err
	}

 not_IKM := flip_bits(IKM)
	lamport_1, err := IKM_to_lamport_SK(not_IKM, salt)
	if err != nil {
		return nil, err
	}

	var lamport_PK []byte
	for i := 0; i < len(lamport_0); i++ {
  sum := sha256.Sum256(lamport_0[i])
  lamport_PK = append(lamport_PK, sum[:]...)
	}

	for i := 0; i < len(lamport_1); i++ {
  sum := sha256.Sum256(lamport_1[i])
  lamport_PK = append(lamport_PK, sum[:]...)
	}

 compressed_lamport_PK := sha256.Sum256(lamport_PK)
 return compressed_lamport_PK[:], nil
}

// 1. salt = "BLS-SIG-KEYGEN-SALT-"
// 2. SK = 0
// 3. while SK == 0:
// 4.     salt = H(salt)
// 5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
// 6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
// 7.     SK = OS2IP(OKM) mod r
// 8. return SK

func HKDF_mod_r(IKM []byte, key_info []byte) *big.Int {
 salt := []byte("BLS-SIG-KEYGEN-SALT-")
	L := 48
	zeroPaddedL := make([]byte, 2)
	binary.BigEndian.PutUint16(zeroPaddedL, uint16(L))

	SK := new(big.Int) // zero initialized
	for SK.BitLen() == 0 {
  saltArr := sha256.Sum256(salt)
  salt = saltArr[:]
  PRK := hkdf.Extract(sha256.New, append(IKM, 0), salt)
		okmReader := hkdf.Expand(sha256.New, PRK, append(key_info, zeroPaddedL...))

		OKM := make([]byte, L)
		_, err := io.ReadFull(okmReader, OKM)
		if err != nil {
			panic(err)
		}

  // SetBytes interprets buf as the bytes of a big-endian unsigned integer, sets z to that value, and returns z, I think it's zero padded
		SK = new(big.Int).SetBytes(OKM)
		SK.Mod(SK, R)
	}
	return SK
}


func padBytes(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	padded := make([]byte, size-len(data))
	return append(padded, data...)
}
func I2OSP(i *big.Int, size int) []byte {
  return padBytes(i.Bytes(), size)
}

// 0. compressed_lamport_PK = parent_SK_to_lamport_PK(parent_SK, index)
// 1. SK = HKDF_mod_r(compressed_lamport_PK)
// 2. return SK
func derive_child_SK(parent_SK *big.Int, index uint32) (child_SK *big.Int, err error) {
	compressed_lamport_PK, err := parent_SK_to_lamport_PK(parent_SK, index)
	if err != nil {
		return nil, err
	}
	return HKDF_mod_r(compressed_lamport_PK, nil), nil
}


// 0. SK = HKDF_mod_r(seed)
// 1. return SK
func derive_master_SK(seed []byte) (SK *big.Int, err error) {
	if len(seed) < 32 {
		return nil, errors.New("`len(seed)` should be greater than or equal to 32.")
	}
	return HKDF_mod_r(seed, nil), nil
}
