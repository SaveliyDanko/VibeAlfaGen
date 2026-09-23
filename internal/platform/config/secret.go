package config

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type kubernetesSecretSource struct {
	client    kubernetes.Interface
	namespace string
	name      string
	key       string
}

func NewKubernetesSecretSource(client kubernetes.Interface, namespace, name, key string) (Source, error) {
	if client == nil {
		return nil, fmt.Errorf("config: kubernetes client is nil")
	}
	if namespace == "" || name == "" || key == "" {
		return nil, fmt.Errorf("config: kubernetes namespace, name and key are required")
	}
	return &kubernetesSecretSource{client: client, namespace: namespace, name: name, key: key}, nil
}

func NewInClusterSecretSource(namespace, name, key string) (Source, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("config: in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("config: kubernetes client: %w", err)
	}
	return NewKubernetesSecretSource(client, namespace, name, key)
}

func (s *kubernetesSecretSource) Read(ctx context.Context) (Document, error) {
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return Document{}, classifyK8sError(err)
	}
	data, ok := secret.Data[s.key]
	if !ok {
		return Document{}, fmt.Errorf("config: kubernetes secret key %q not found", s.key)
	}
	if len(data) == 0 {
		return Document{}, fmt.Errorf("config: kubernetes secret key %q is empty", s.key)
	}
	copyData := make([]byte, len(data))
	copy(copyData, data)
	return Document{Data: copyData, Format: "json", Revision: secret.ResourceVersion}, nil
}

func classifyK8sError(err error) error {
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("config: kubernetes secret not_found")
	}
	if apierrors.IsForbidden(err) {
		return fmt.Errorf("config: kubernetes secret forbidden")
	}
	if apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsServiceUnavailable(err) {
		return fmt.Errorf("config: kubernetes secret unavailable")
	}
	return fmt.Errorf("config: kubernetes secret invalid")
}
