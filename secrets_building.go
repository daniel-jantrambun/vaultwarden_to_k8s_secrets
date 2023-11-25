// Copyright (c) 2023, Benjamin Darnault <daniel.jantrambun@pm.me>
// See LICENSE for licensing information

package main

import (
	"fmt"
	"log/slog"
	"strings"
)

func buildCollections(collectionPrefix string) (map[string]vaultCollection, error) {
	collections := make(map[string]vaultCollection)
	for _, collection := range secrets.data.Sync.Collections {
		collectionName, err := secrets.decrypt(collection.Name, collection.OrganizationID)
		if err != nil {
			err = fmt.Errorf("Collection name decryption error %v", err)
			return nil, err
		}
		if strings.HasPrefix(string(collectionName[:]), collectionPrefix) {
			collectionNameSplit := strings.Split(string(collectionName[:]), "/")
			if len(collectionNameSplit) != 3 {
				fmt.Println("Collection name is not in the correct format", string(collectionName[:]))
				return nil, fmt.Errorf("Collection name is not in the correct format %s", string(collectionName[:]))
			}
			slog.Info(fmt.Sprint("Collection name", string(collectionName[:])))
			collections[collection.ID.String()] = collection
		}
	}
	return collections, nil
}

func buildK8sSecrets(collectionIDs map[string]vaultCollection) ([]k8sSecret, error) {
	var k8sSecrets []k8sSecret
	for _, cipher := range secrets.data.Sync.Ciphers {
		for _, cipherCollectionID := range cipher.CollectionIDs {
			for collectionID, collection := range collectionIDs {
				if collectionID == cipherCollectionID.String() {
					decryptedCollectionName, err := secrets.decrypt(collection.Name, collection.OrganizationID)
					if err != nil {
						slog.Error(fmt.Sprint("Collection name decryption error", err))
						return nil, err
					}
					collectionNameSplit := strings.Split(string(decryptedCollectionName[:]), "/")
					secretName := collectionNameSplit[2]

					newK8sSecretData, err := getSecretData(cipher)
					if err != nil {
						slog.Error(fmt.Sprint("Error getting secret data", err))
						return nil, err
					}
					k8sSecrets = addOrUpdateSecretes(k8sSecrets, secretName, *newK8sSecretData)
				}
			}
		}
	}
	return k8sSecrets, nil
}

// getSecretData decrypts the secret name and value from the vault cipher
// We use Login.Username as the secret name and Login.Password as the secret value
// The vault secret Name is not used to create k8s secret.
func getSecretData(cipher vaultCipher) (*k8sSecretData, error) {
	secretName, err := secrets.decrypt(cipher.Login.Username, cipher.OrganizationID)
	if err != nil {
		slog.Error(fmt.Sprint("cipher name decryption error", err))
		return nil, err
	}
	secretValue, err := secrets.decrypt(cipher.Login.Password, cipher.OrganizationID)
	if err != nil {
		slog.Error(fmt.Sprint("cipher password decryption error", err))
		return nil, err
	}
	return &k8sSecretData{
		key:   string(secretName[:]),
		value: string(secretValue[:]),
	}, nil
}

func addOrUpdateSecretes(k8sSecrets []k8sSecret, secretName string, newK8sSecretData k8sSecretData) []k8sSecret {
	for i, secret := range k8sSecrets {
		if secret.name == secretName {
			secret.data = append(secret.data, newK8sSecretData)
			k8sSecrets[i] = secret
			return k8sSecrets
		}
	}

	k8sSecret := k8sSecret{
		name: secretName,
		data: []k8sSecretData{newK8sSecretData},
	}
	return append(k8sSecrets, k8sSecret)
}
