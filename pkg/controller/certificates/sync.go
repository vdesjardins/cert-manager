package certificates

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorIssuerNotFound       = "ErrIssuerNotFound"
	errorIssuerNotReady       = "ErrIssuerNotReady"
	errorIssuerInit           = "ErrIssuerInitialization"
	errorCheckCertificate     = "ErrCheckCertificate"
	errorGetCertificate       = "ErrGetCertificate"
	errorPreparingCertificate = "ErrPrepareCertificate"
	errorIssuingCertificate   = "ErrIssueCertificate"
	errorRenewingCertificate  = "ErrRenewCertificate"
	errorSavingCertificate    = "ErrSaveCertificate"

	reasonPreparingCertificate = "PrepareCertificate"
	reasonIssuingCertificate   = "IssueCertificate"
	reasonRenewingCertificate  = "RenewCertificate"

	successCertificateIssued  = "CertificateIssued"
	successCertificateRenewed = "CertificateRenewed"
	successRenewalScheduled   = "RenewalScheduled"

	warningCertificateDuration = "WarnCertificateDuration"
	warningScheduleModified    = "WarnScheduleModified"

	messageIssuerNotFound            = "Issuer %s does not exist"
	messageIssuerNotReady            = "Issuer %s not ready"
	messageIssuerErrorInit           = "Error initializing issuer: "
	messageErrorCheckCertificate     = "Error checking existing TLS certificate, will re-issue: "
	messageErrorGetCertificate       = "Error getting TLS certificate: "
	messageErrorPreparingCertificate = "Error preparing issuer for certificate: "
	messageErrorIssuingCertificate   = "Error issuing certificate: "
	messageErrorRenewingCertificate  = "Error renewing certificate: "
	messageErrorSavingCertificate    = "Error saving TLS certificate: "

	messagePreparingCertificate = "Preparing certificate with issuer"
	messageIssuingCertificate   = "Issuing certificate..."
	messageRenewingCertificate  = "Renewing certificate..."

	messageCertificateIssued  = "Certificate issued successfully"
	messageCertificateRenewed = "Certificate renewed successfully"
	messageRenewalScheduled   = "Certificate scheduled for renewal in %d hours"

	messageWarningCertificateDuration = "Certificate duration received from issuer is %s which is lower than the issuer configured duration of %s"
	messageWarningScheduleModified    = "Certificate renewal requested schedule cannot be honored. Specified renewBefore of %s is greater than certificate total duration of %s"
)

// to help testing
var now = time.Now

func (c *Controller) Sync(ctx context.Context, crt *v1alpha1.Certificate) (err error) {
	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.getGenericIssuer(crt)

	if err != nil {
		s := fmt.Sprintf(messageIssuerNotFound, err.Error())
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerNotFound, s)
		return err
	}

	issuerReady := issuerObj.HasCondition(v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	if !issuerReady {
		s := fmt.Sprintf(messageIssuerNotReady, issuerObj.GetObjectMeta().Name)
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerNotReady, s)
		return fmt.Errorf(s)
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)
	if err != nil {
		s := messageIssuerErrorInit + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerInit, s)
		return err
	}

	expectedCN, err := pki.CommonNameForCertificate(crt)
	if err != nil {
		return err
	}
	expectedDNSNames, err := pki.DNSNamesForCertificate(crt)
	if err != nil {
		return err
	}

	// grab existing certificate and validate private key
	cert, err := kube.SecretTLSCert(c.secretLister, crt.Namespace, crt.Spec.SecretName)
	if err != nil {
		s := messageErrorCheckCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeNormal, errorCheckCertificate, s)
	}

	// if an error is returned, and that error is something other than
	// IsNotFound or invalid data, then we should return the error.
	if err != nil && !k8sErrors.IsNotFound(err) && !errors.IsInvalidData(err) {
		return err
	}

	// as there is an existing certificate, or we may create one below, we will
	// run scheduleRenewal to schedule a renewal if required at the end of
	// execution.
	defer c.scheduleRenewal(crt, issuerObj)

	crtCopy := crt.DeepCopy()

	// if the certificate was not found, or the certificate data is invalid, we
	// should issue a new certificate.
	// if the certificate is valid for a list of domains other than those
	// listed in the certificate spec, we should re-issue the certificate.
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) ||
		expectedCN != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) {
		err := c.issue(ctx, i, crtCopy)
		updateErr := c.updateCertificateStatus(crtCopy)
		if err != nil || updateErr != nil {
			return utilerrors.NewAggregate([]error{err, updateErr})
		}
		return nil
	}

	renewIn := c.calculateTimeBeforeExpiry(cert, crtCopy, issuerObj)

	// if we should being attempting to renew now, then trigger a renewal
	if renewIn <= 0 {
		err := c.renew(ctx, i, crtCopy)
		updateErr := c.updateCertificateStatus(crtCopy)
		if err != nil || updateErr != nil {
			return utilerrors.NewAggregate([]error{err, updateErr})
		}
	}

	return nil
}

func (c *Controller) getGenericIssuer(crt *v1alpha1.Certificate) (v1alpha1.GenericIssuer, error) {
	switch crt.Spec.IssuerRef.Kind {
	case "", v1alpha1.IssuerKind:
		return c.issuerLister.Issuers(crt.Namespace).Get(crt.Spec.IssuerRef.Name)
	case v1alpha1.ClusterIssuerKind:
		if c.clusterIssuerLister == nil {
			return nil, fmt.Errorf("cannot get ClusterIssuer for %q as cert-manager is scoped to a single namespace", crt.Name)
		}
		return c.clusterIssuerLister.Get(crt.Spec.IssuerRef.Name)
	default:
		return nil, fmt.Errorf(`invalid value %q for certificate issuer kind. Must be empty, %q or %q`, crt.Spec.IssuerRef.Kind, v1alpha1.IssuerKind, v1alpha1.ClusterIssuerKind)
	}
}

func (c *Controller) scheduleRenewal(crt *v1alpha1.Certificate, issuer v1alpha1.GenericIssuer) {
	key, err := keyFunc(crt)

	if err != nil {
		runtime.HandleError(fmt.Errorf("error getting key for certificate resource: %s", err.Error()))
		return
	}

	cert, err := kube.SecretTLSCert(c.secretLister, crt.Namespace, crt.Spec.SecretName)

	if err != nil {
		runtime.HandleError(fmt.Errorf("[%s/%s] Error getting certificate '%s': %s", crt.Namespace, crt.Name, crt.Spec.SecretName, err.Error()))
		return
	}

	renewIn := c.calculateTimeBeforeExpiry(cert, crt, issuer)

	c.scheduledWorkQueue.Add(key, renewIn)

	s := fmt.Sprintf(messageRenewalScheduled, renewIn/time.Hour)
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, successRenewalScheduled, s)
}

func (c *Controller) updateSecret(name, namespace string, cert, key []byte) (*api.Secret, error) {
	secret, err := c.client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}
	if k8sErrors.IsNotFound(err) {
		secret = &api.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: api.SecretTypeTLS,
			Data: map[string][]byte{},
		}
	}
	secret.Data[api.TLSCertKey] = cert
	secret.Data[api.TLSPrivateKeyKey] = key
	// if it is a new resource
	if secret.SelfLink == "" {
		secret, err = c.client.CoreV1().Secrets(namespace).Create(secret)
	} else {
		secret, err = c.client.CoreV1().Secrets(namespace).Update(secret)
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) issue(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	var err error
	s := messagePreparingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonPreparingCertificate, s)
	if err = issuer.Prepare(ctx, crt); err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}

	s = messageIssuingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonIssuingCertificate, s)

	var key, cert []byte
	key, cert, err = issuer.Issue(ctx, crt)

	if err != nil {
		s := messageErrorIssuingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuingCertificate, s)
		return err
	}

	if _, err := c.updateSecret(crt.Spec.SecretName, crt.Namespace, cert, key); err != nil {
		s := messageErrorSavingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	s = messageCertificateIssued
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, successCertificateIssued, s)

	return nil
}

// renew will attempt to renew a certificate from the specified issuer, or
// return an error on failure. If renewal is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) renew(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	var err error
	s := messagePreparingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonPreparingCertificate, s)

	if err = issuer.Prepare(ctx, crt); err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}

	s = messageRenewingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonRenewingCertificate, s)

	var key, cert []byte
	key, cert, err = issuer.Renew(ctx, crt)

	if err != nil {
		s := messageErrorRenewingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorRenewingCertificate, s)
		return err
	}

	if _, err := c.updateSecret(crt.Spec.SecretName, crt.Namespace, cert, key); err != nil {
		s := messageErrorSavingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	s = messageCertificateRenewed
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, successCertificateRenewed, s)

	return nil
}

func (c *Controller) updateCertificateStatus(crt *v1alpha1.Certificate) error {
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	_, err := c.cmClient.CertmanagerV1alpha1().Certificates(crt.Namespace).Update(crt)
	return err
}

func (c *Controller) calculateTimeBeforeExpiry(cert *x509.Certificate, crt *v1alpha1.Certificate, issuerObj v1alpha1.GenericIssuer) time.Duration {
	// validate if the certificate received was with the issuer configured
	// duration. If not we generate an event to warn the user of that fact.
	certDuration := cert.NotAfter.Sub(cert.NotBefore)
	if certDuration < issuerObj.GetSpec().Duration {
		s := fmt.Sprintf(messageWarningCertificateDuration, certDuration, issuerObj.GetSpec().Duration)
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, warningCertificateDuration, s)
	}

	// renew is the duration before the certificate expiration that cert-manager
	// will start to try renewing the certificate.
	renew := issuer.RenewCertificateBeforeDuration
	if issuerObj.GetSpec().RenewBefore != 0 {
		renew = issuerObj.GetSpec().RenewBefore
	}

	// Verify that the renewBefore duration is inside the certificate validity duration.
	// If not we notify with an event that we will renew the certificate
	// before (certificate duration / 3) of its expiration duration.
	if renew > certDuration {
		s := fmt.Sprintf(messageWarningScheduleModified, renew, certDuration)
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, warningScheduleModified, s)
		// We will renew 1/3 before the expiration date.
		renew = certDuration / 3
	}

	// calculate the amount of time until expiry
	durationUntilExpiry := cert.NotAfter.Sub(now())

	// calculate how long until we should start attempting to renew the
	// certificate
	renewIn := durationUntilExpiry - renew

	return renewIn
}
