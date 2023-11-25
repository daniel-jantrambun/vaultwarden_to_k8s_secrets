// Copyright (c) 2023, Benjamin Darnault <daniel.jantrambun@pm.me>
// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// KDFType is the type of key derivation function used to derive the master key
type KDFType int

// KDF types
const (
	KDFTypePBKDF2   KDFType = 0
	KDFTypeArgon2id KDFType = 1
)

type secretCache struct {
	data *dataFile

	_password     []byte
	_email        string
	_clientID     []byte
	_clientSecret []byte

	key    []byte
	macKey []byte

	privateKey *rsa.PrivateKey
	orgKeys    map[string][]byte
	orgMacKeys map[string][]byte
}

func (c *secretCache) email() (string, error) {
	if c._email != "" {
		return c._email, nil
	}
	if s := os.Getenv("EMAIL"); s != "" {
		c._email = s
		return c._email, nil
	}
	return "", fmt.Errorf("email not set")
}

func (c *secretCache) password() ([]byte, error) {
	if c._password != nil {
		return c._password, nil
	}
	if s := os.Getenv("PASSWORD"); s != "" {
		c._password = []byte(s)
		return c._password, nil
	}
	return nil, fmt.Errorf("password not set")
}

func (c *secretCache) clientID() ([]byte, error) {
	if c._clientID != nil {
		return c._clientID, nil
	}
	if s := os.Getenv("CLIENT_ID"); s != "" {
		c._clientID = []byte(s)
		return c._clientID, nil
	}
	return nil, fmt.Errorf("client_id not set")
}

func (c *secretCache) clientSecret() ([]byte, error) {
	if c._clientSecret != nil {
		return c._clientSecret, nil
	}
	if s := os.Getenv("CLIENT_SECRET"); s != "" {
		c._clientSecret = []byte(s)
		return c._clientSecret, nil
	}
	return nil, fmt.Errorf("client_secret not set")
}

func (c *secretCache) initKeys() error {
	if c.key != nil {
		return nil
	}

	keyCipher := globalData.Sync.Profile.Key
	switch keyCipher.Type {
	case AesCbc256B64, AesCbc256HmacSha256B64:
	default:
		return fmt.Errorf("unsupported key cipher type %q", keyCipher.Type)
	}

	email, _ := c.email()
	if email == "" {
		return fmt.Errorf("need a configured email or $EMAIL to decrypt data")
	}
	password, err := c.password()
	if err != nil {
		return err
	}

	masterKey, err := deriveMasterKey(password, email, globalData.KDF, globalData.KDFIterations, globalData.KDFMemory, globalData.KDFParallelism)
	if err != nil {
		return err
	}

	var finalKey []byte
	switch keyCipher.Type {
	case AesCbc256B64:
		finalKey, err = decryptWith(keyCipher, masterKey, nil)
		if err != nil {
			return err
		}
	case AesCbc256HmacSha256B64:
		// We decrypt the decryption key from the synced data, using the key
		// resulting from stretching masterKey. The keys are discarded once we
		// obtain the final ones.
		key, macKey := stretchKey(masterKey)

		finalKey, err = decryptWith(keyCipher, key, macKey)
		if err != nil {
			return err
		}
	}

	switch len(finalKey) {
	case 32:
		c.key = finalKey
	case 64:
		c.key, c.macKey = finalKey[:32], finalKey[32:64]
	default:
		return fmt.Errorf("invalid key length: %d", len(finalKey))
	}

	if !c.data.Sync.Profile.PrivateKey.IsZero() {
		pkcs8PrivateKey, err := secrets.decrypt(c.data.Sync.Profile.PrivateKey, nil)
		if err != nil {
			return err
		}
		key, err := x509.ParsePKCS8PrivateKey(pkcs8PrivateKey)
		if err != nil {
			return err
		}
		c.privateKey = key.(*rsa.PrivateKey)
		c.orgKeys = make(map[string][]byte)
		c.orgMacKeys = make(map[string][]byte)

		for _, organization := range c.data.Sync.Profile.Organizations {
			// the first byte is the encryption type (always 4 at the moment)
			// the second byte is a separator
			var keyString = organization.Key[2:]

			decodedData, err := base64.StdEncoding.DecodeString(keyString)
			if err != nil {
				return err
			}

			res, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, c.privateKey, decodedData, nil)
			if err != nil {
				return err
			}

			c.orgKeys[organization.ID.String()] = res[0:32]
			c.orgMacKeys[organization.ID.String()] = res[32:64]
		}
	}

	return nil
}

func deriveMasterKey(password []byte, email string, kdfType KDFType, iter int, mem int, par int) ([]byte, error) {
	switch kdfType {
	case KDFTypePBKDF2:
		return pbkdf2.Key(password, []byte(strings.ToLower(email)), iter, 32, sha256.New), nil
	case KDFTypeArgon2id:
		var salt [32]byte = sha256.Sum256([]byte(strings.ToLower(email)))
		return argon2.IDKey(password, salt[:], uint32(iter), uint32(mem*1024), uint8(par), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", kdfType)
	}
}

func stretchKey(orig []byte) (key, macKey []byte) {
	key = make([]byte, 32)
	macKey = make([]byte, 32)
	var r io.Reader
	r = hkdf.Expand(sha256.New, orig, []byte("enc"))
	r.Read(key)
	r = hkdf.Expand(sha256.New, orig, []byte("mac"))
	r.Read(macKey)
	return key, macKey
}

func (c *secretCache) decryptStr(s cipherString, orgID *uuid.UUID) (string, error) {
	dec, err := c.decrypt(s, orgID)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func (c *secretCache) decrypt(s cipherString, orgID *uuid.UUID) ([]byte, error) {
	if s.IsZero() {
		return nil, nil
	}
	if err := c.initKeys(); err != nil {
		return nil, err
	}
	if orgID != nil {
		return decryptWith(s, c.orgKeys[orgID.String()], c.orgMacKeys[orgID.String()])
	}
	return decryptWith(s, c.key, c.macKey)
}

func decryptWith(s cipherString, key, macKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch s.Type {
	case AesCbc256B64, AesCbc256HmacSha256B64:
		// continues below
	default:
		return nil, fmt.Errorf("decrypt: unsupported cipher type %q", s.Type)
	}

	if s.Type == AesCbc256HmacSha256B64 {
		if len(s.MAC) == 0 || len(macKey) == 0 {
			return nil, fmt.Errorf("decrypt: cipher string type expects a MAC")
		}
		var msg []byte
		msg = append(msg, s.IV...)
		msg = append(msg, s.CT...)
		if !validMAC(msg, s.MAC, macKey) {
			return nil, fmt.Errorf("decrypt: MAC mismatch")
		}
	}

	mode := cipher.NewCBCDecrypter(block, s.IV)
	dst := make([]byte, len(s.CT))
	mode.CryptBlocks(dst, s.CT)
	dst, err = unpadPKCS7(dst, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func unpadPKCS7(src []byte, size int) ([]byte, error) {
	n := src[len(src)-1]
	if len(src)%size != 0 {
		return nil, fmt.Errorf("expected PKCS7 padding for block size %d, but have %d bytes", size, len(src))
	}
	if len(src) <= int(n) {
		return nil, fmt.Errorf("cannot unpad %d bytes out of a total of %d", n, len(src))
	}
	src = src[:len(src)-int(n)]
	return src, nil
}

func padPKCS7(src []byte, size int) []byte {
	// Note that we always pad, even if rem==0. This is because unpad must
	// always remove at least one byte to be unambiguous.
	rem := len(src) % size
	n := size - rem
	if n > math.MaxUint8 {
		panic(fmt.Sprintf("cannot pad over %d bytes, but got %d", math.MaxUint8, n))
	}
	padded := make([]byte, len(src)+n)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

func validMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
