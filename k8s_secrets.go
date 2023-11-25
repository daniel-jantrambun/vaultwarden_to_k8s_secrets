// Copyright (c) 2023, Benjamin Darnault <daniel.jantrambun@pm.me>
// See LICENSE for licensing information

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"time"

	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func getClientset() (clientset *kubernetes.Clientset, err error) {
	slog.Debug(fmt.Sprint("Using out-of-cluster mode"))
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Error(fmt.Sprintf("error getting user home dir: %v\n", err))
		return nil, err
	}
	kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
	slog.Debug(fmt.Sprintf("Using kubeConfig: %s\n", kubeConfigPath))

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		err = fmt.Errorf("error getting kubernetes config: %v", err)
		return nil, err
	}
	clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		err = fmt.Errorf("error getting kubernetes client out cluster: %v", err)
		return nil, err
	}
	return clientset, err
}

func setK8sSecret(namespace string, secret *coreV1.Secret, client *kubernetes.Clientset) (*coreV1.Secret, error) {
	slog.Info(fmt.Sprintf("Checks Kubernetes secret %v:%v\n", namespace, secret.Name))
	s, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})

	if err == nil {
		newSecret, err := client.CoreV1().Secrets(namespace).Update(context.Background(), secret, metav1.UpdateOptions{})
		if err != nil {
			err = fmt.Errorf("error updating secret: %v", err)
			return nil, err
		}

		if reflect.DeepEqual(newSecret.Data, s.Data) {
			slog.Info(fmt.Sprintf("secret %v is up to date", secret.Name))
		} else {
			slog.Info(fmt.Sprintf("secret %v has been updated", secret.Name))
		}
		return newSecret, nil
	}

	newSecret, err := client.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		slog.Error(fmt.Sprint("error getting secret: ", err))
		return nil, err
	}

	slog.Info("secret set successfully")
	return newSecret, nil
}

func setK8sSecrets(currentNamespace string, k8sSecrets []k8sSecret) error {
	clientset, err := getClientset()
	if err != nil {
		slog.Error(fmt.Sprint("error getting kubernetes client", err))
		return err
	}

	for _, k8sSecret := range k8sSecrets {
		var secretSpec coreV1.Secret
		secretSpec.Name = k8sSecret.name
		secretSpec.Data = make(map[string][]byte)
		secretSpec.Type = coreV1.SecretTypeOpaque
		secretSpec.ObjectMeta = metav1.ObjectMeta{
			Name: k8sSecret.name,
		}
		secretSpec.Annotations = map[string]string{
			"vault-sync": "true",
			"last-sync":  time.Now().UTC().Format(time.RFC3339),
		}

		for _, k8sSecretData := range k8sSecret.data {
			secretSpec.Data[k8sSecretData.key] = []byte(k8sSecretData.value)
		}
		secret, err := setK8sSecret(currentNamespace, &secretSpec, clientset)
		if err != nil {
			slog.Error(fmt.Sprint("error setting secret: ", err))
			return err
		}
		slog.Debug(fmt.Sprintf("installed secret %v:%v\n", secret.Namespace, secret.Name))
	}
	return nil
}
