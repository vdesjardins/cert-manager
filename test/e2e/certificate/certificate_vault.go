package certificate

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
)

var _ = framework.CertManagerDescribe("Vault Certificate (Token)", func() {
	f := framework.NewDefaultFramework("create-vault-certificate")

	rootMount := "root-ca"
	intermediateMount := "intermediate-ca"
	role := "kubernetes-vault"
	issuerName := "test-vault-issuer"
	certificateName := "test-vault-certificate"
	certificateSecretName := "test-vault-certificate"
	vaultSecretTokenName := "vault-token"
	vaultPath := fmt.Sprintf("%s/sign/%s", intermediateMount, role)
	var vaultInit *util.VaultInitializer

	BeforeEach(func() {
		By("Configuring the Vault server")
		podList, err := f.KubeClientSet.CoreV1().Pods("vault").List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		vaultPodName := podList.Items[0].Name
		vaultInit, err = util.NewVaultInitializer(vaultPodName, rootMount, intermediateMount, role)
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(util.NewVaultTokenSecret(vaultSecretTokenName))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(vaultSecretTokenName, nil)
		vaultInit.Clean()
	})

	vaultURL := "http://vault.vault:8200"
	cases := []struct {
		inputDuration    time.Duration
		expectedDuration time.Duration
		label            string
	}{
		{time.Hour * 24 * 35, time.Hour * 24 * 35, "35 days"},
		{0, time.Hour * 24 * 90, "the default value (90 days)"},
	}

	for _, v := range cases {
		v := v
		It("should generate a new certificate valid for "+v.label, func() {
			By("Creating an Issuer")
			_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerToken(issuerName, vaultURL, vaultPath, vaultSecretTokenName, v.inputDuration))
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerName,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v1alpha1.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Certificate")
			cert, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind))
			Expect(err).NotTo(HaveOccurred())

			f.WaitCertificateIssuedValid(cert)
			// Vault substract 30 seconds to the NotBefore date.
			f.CertificateDurationValid(cert, v.expectedDuration+(30*time.Second))
		})
	}
})

var _ = framework.CertManagerDescribe("Vault Certificate (AppRole)", func() {
	f := framework.NewDefaultFramework("create-vault-certificate")

	rootMount := "root-ca"
	intermediateMount := "intermediate-ca"
	role := "kubernetes-vault"
	issuerName := "test-vault-issuer"
	certificateName := "test-vault-certificate"
	certificateSecretName := "test-vault-certificate"
	vaultSecretAppRoleName := "vault-role"
	vaultPath := fmt.Sprintf("%s/sign/%s", intermediateMount, role)
	var vaultInit *util.VaultInitializer

	BeforeEach(func() {
		By("Configuring the Vault server")
		podList, err := f.KubeClientSet.CoreV1().Pods("vault").List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		vaultPodName := podList.Items[0].Name
		vaultInit, err = util.NewVaultInitializer(vaultPodName, rootMount, intermediateMount, role)
		Expect(err).NotTo(HaveOccurred())
		err = vaultInit.Setup()
		Expect(err).NotTo(HaveOccurred())
		roleId, secretId, err := vaultInit.CreateAppRole()
		Expect(err).NotTo(HaveOccurred())
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(util.NewVaultAppRoleSecret(vaultSecretAppRoleName, roleId, secretId))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(vaultSecretAppRoleName, nil)
		vaultInit.CleanAppRole()
		vaultInit.Clean()
	})

	vaultURL := "http://vault.vault:8200"
	cases := []struct {
		inputDuration    time.Duration
		expectedDuration time.Duration
		label            string
	}{
		{time.Hour * 24 * 35, time.Hour * 24 * 35, "35 days"},
		{0, time.Hour * 24 * 90, "the default value (90 days)"},
	}

	for _, v := range cases {
		v := v
		It("should generate a new certificate valid for "+v.label, func() {
			By("Creating an Issuer")
			_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerVaultIssuerAppRole(issuerName, vaultURL, vaultPath, vaultSecretAppRoleName, v.inputDuration))
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerName,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v1alpha1.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Certificate")
			cert, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(util.NewCertManagerVaultCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind))
			Expect(err).NotTo(HaveOccurred())

			f.WaitCertificateIssuedValid(cert)
			// Vault substract 30 seconds to the NotBefore date.
			f.CertificateDurationValid(cert, v.expectedDuration+(30*time.Second))
		})
	}
})
