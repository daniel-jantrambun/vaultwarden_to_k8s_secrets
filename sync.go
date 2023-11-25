// Copyright (c) 2023, Benjamin Darnault <daniel.jantrambun@pm.me>
// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type syncData struct {
	Profile     profile
	Folders     []vaultFolder
	Ciphers     []vaultCipher
	Collections []vaultCollection
}

type cipherString struct {
	Type cipherStringType

	IV, CT, MAC []byte
}

type cipherStringType int

// Taken from https://github.com/bitwarden/jslib/blob/f30d6f8027055507abfdefd1eeb5d9aab25cc601/src/enums/encryptionType.ts
const (
	AesCbc256B64                   cipherStringType = 0
	AesCbc128HmacSha256B64         cipherStringType = 1
	AesCbc256HmacSha256B64         cipherStringType = 2
	Rsa2048OaepSha256B64           cipherStringType = 3
	Rsa2048OaepSha1B64             cipherStringType = 4
	Rsa2048OaepSha256HmacSha256B64 cipherStringType = 5
	Rsa2048OaepSha1HmacSha256B64   cipherStringType = 6
)

func (t cipherStringType) HasMAC() bool {
	return t != AesCbc256B64
}

func (s cipherString) IsZero() bool {
	return s.Type == 0 && s.IV == nil && s.CT == nil && s.MAC == nil
}

func (s cipherString) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s cipherString) String() string {
	if s.IsZero() {
		return ""
	}
	if !s.Type.HasMAC() {
		return fmt.Sprintf("%d.%s|%s",
			s.Type,
			b64enc.EncodeToString(s.IV),
			b64enc.EncodeToString(s.CT),
		)
	}
	return fmt.Sprintf("%d.%s|%s|%s",
		s.Type,
		b64enc.EncodeToString(s.IV),
		b64enc.EncodeToString(s.CT),
		b64enc.EncodeToString(s.MAC),
	)
}

func (s *cipherString) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	i := bytes.IndexByte(data, '.')
	if i < 0 {
		return fmt.Errorf("cipher string does not contain a type: %q", data)
	}
	typStr := string(data[:i])
	var err error
	var t int
	if t, err = strconv.Atoi(typStr); err != nil {
		return fmt.Errorf("invalid cipher string type: %q", typStr)
	}
	s.Type = cipherStringType(t)

	switch s.Type {
	case AesCbc128HmacSha256B64, AesCbc256HmacSha256B64, AesCbc256B64:
	default:
		return fmt.Errorf("unsupported cipher string type: %d", s.Type)
	}

	data = data[i+1:]
	parts := bytes.Split(data, []byte("|"))
	wantParts := 3
	if !s.Type.HasMAC() {
		wantParts = 2
	}
	if len(parts) != wantParts {
		return fmt.Errorf("cipher string type requires %d parts: %q", wantParts, data)
	}

	// TODO: do a single []byte allocation for all fields
	if s.IV, err = b64decode(parts[0]); err != nil {
		return err
	}
	if s.CT, err = b64decode(parts[1]); err != nil {
		return err
	}
	if s.Type.HasMAC() {
		if s.MAC, err = b64decode(parts[2]); err != nil {
			return err
		}
	}
	return nil
}

func b64decode(src []byte) ([]byte, error) {
	dst := make([]byte, b64enc.DecodedLen(len(src)))
	n, err := b64enc.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	dst = dst[:n]
	return dst, nil
}

// Organization represents a Bitwarden organization.
type Organization struct {
	Object          string
	ID              uuid.UUID
	Name            string
	UseGroups       bool
	UseDirectory    bool
	UseEvents       bool
	UseTotp         bool
	Use2fa          bool
	UseAPI          bool
	UsersGetPremium bool
	SelfHost        bool
	Seats           int
	MaxCollections  int
	MaxStorageGb    int
	Key             string
	Status          int
	Type            int
	Enabled         bool
}

type profile struct {
	ID                 uuid.UUID
	Name               string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint string
	Culture            string
	TwoFactorEnabled   bool
	Key                cipherString
	PrivateKey         cipherString
	SecurityStamp      string
	Organizations      []Organization
}

type vaultFolder struct {
	ID           uuid.UUID
	Name         string
	RevisionDate time.Time
}
type vaultCollection struct {
	ID             *uuid.UUID
	Name           cipherString
	ExternalID     string
	HidePassword   bool
	Object         string
	OrganizationID *uuid.UUID
	ReadOnly       bool
}

type vaultCipher struct {
	Type         cipherType
	ID           uuid.UUID
	Name         cipherString
	Edit         bool
	RevisionDate time.Time

	// The rest of the fields are optional. Omit from the JSON if empty.

	FolderID            *uuid.UUID   `json:",omitempty"`
	OrganizationID      *uuid.UUID   `json:",omitempty"`
	Favorite            bool         `json:",omitempty"`
	Attachments         interface{}  `json:",omitempty"`
	OrganizationUseTotp bool         `json:",omitempty"`
	CollectionIDs       []*uuid.UUID `json:",omitempty"`
	Fields              []field      `json:",omitempty"`

	Card       *card         `json:",omitempty"`
	Identity   *identity     `json:",omitempty"`
	Login      *login        `json:",omitempty"`
	Notes      *cipherString `json:",omitempty"`
	SecureNote *secureNote   `json:",omitempty"`
}

type cipherType int

const (
	_ cipherType = iota
	cipherLogin
	cipherCard
	cipherIdentity
	cipherNote
)

type card struct {
	CardholderName cipherString
	Brand          cipherString
	Number         cipherString
	ExpMonth       cipherString
	ExpYear        cipherString
	Code           cipherString
}

type identity struct {
	Title      cipherString
	FirstName  cipherString
	MiddleName cipherString
	LastName   cipherString

	Username       cipherString
	Company        cipherString
	SSN            cipherString
	PassportNumber cipherString
	LicenseNumber  cipherString

	Email      cipherString
	Phone      cipherString
	Address1   cipherString
	Address2   cipherString
	Address3   cipherString
	City       cipherString
	State      cipherString
	PostalCode cipherString
	Country    cipherString
}

func (c *vaultCipher) Match(attr, value string) bool {
	got := ""
	var err error
	switch attr {
	case "id":
		got = c.ID.String()
	case "name":
		got, err = secrets.decryptStr(c.Name, c.OrganizationID)
	case "username":
		got, err = secrets.decryptStr(c.Login.Username, c.OrganizationID)
	default:
		return false
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt %s: %v\n", attr, err)
		return false
	}
	return got == value
}

type field struct {
	Type  fieldType
	Name  cipherString
	Value cipherString
}

type fieldType int

type login struct {
	Password cipherString
	URI      cipherString
	URIs     []uri
	Username cipherString `json:",omitempty"`
	Totp     string       `json:",omitempty"`
}

type uri struct {
	URI   string
	Match uriMatch
}

type uriMatch int

type secureNote struct {
	Type secureNoteType
}

type secureNoteType int

func sync(ctx context.Context) error {
	if err := jsonGET(ctx, apiURL+"/sync", &globalData.Sync); err != nil {
		return fmt.Errorf("could not sync: %v", err)
	}
	return nil
}
