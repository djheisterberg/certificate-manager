import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

package com.github.djheisterberg.certificatemanager {
  package util {

    trait CertificateBuilderTestHelper {

      protected val year = 365 * 24 * 60 * 60 * 1000L

      protected val rootAlias = "CA"
      protected val signerAlias = "Signer"
      protected val serverAlias = "Server"
      protected val clientAlias = "Client"

      protected val rootSubject = new X500Principal(s"C=US, CN=$rootAlias")
      protected val signerSubject = new X500Principal(s"C=US, CN=$signerAlias")
      protected val serverSubject = new X500Principal(s"C=US, CN=$serverAlias")
      protected val clientSubject = new X500Principal(s"C=US, CN=$clientAlias")
      protected val notBefore = new Date(1000 * (System.currentTimeMillis() / 1000))
      protected val notAfter = new Date(notBefore.getTime + year)

      protected val rsaSignatureAlgorithm = "SHA256withRSA"
      protected val dsaSignatureAlgorithm = "SHA1withDSA"
      protected val ecSignatureAlgorithm = "SHA256withECDSA"

      protected val digitalSignatureIX = 0
      protected val keyEnciphermentIX = 2
      protected val keyCertSignIX = 5
      protected val keyServerAuthOID = "1.3.6.1.5.5.7.3.1"

      protected def buildRootCertificate(keyPair: KeyPair, signatureAlgorithm: String) = {
        val certificateBuilder = CertificateBuilder.buildSignerCertificate(None, rootSubject, Some(rootAlias), notBefore, notAfter, keyPair.getPublic)
        CertificateBuilder.signCertificate(certificateBuilder, signatureAlgorithm, keyPair.getPrivate)
      }

      protected def buildSignerCertificate(suppliedCertificate: Option[X509Certificate], keyPair: KeyPair, signatureAlgorithm: String) = {
        val issuerCertificate = suppliedCertificate.getOrElse(buildRootCertificate(keyPair, signatureAlgorithm))
        val certificateBuilder = CertificateBuilder.buildSignerCertificate(Some(issuerCertificate), signerSubject, Some(signerAlias), notBefore, notAfter, keyPair.getPublic)
        CertificateBuilder.signCertificate(certificateBuilder, signatureAlgorithm, keyPair.getPrivate)

      }
      protected def buildServerCertificate(suppliedCertificate: Option[X509Certificate], keyPair: KeyPair, signatureAlgorithm: String) = {
        val issuerCertificate = suppliedCertificate.getOrElse(buildRootCertificate(keyPair, signatureAlgorithm))
        val certificateBuilder = CertificateBuilder.buildServerCertificate(issuerCertificate, serverSubject, Some(serverAlias), notBefore, notAfter, keyPair.getPublic)
        CertificateBuilder.signCertificate(certificateBuilder, signatureAlgorithm, keyPair.getPrivate)
      }

      protected def buildClientCertificate(suppliedCertificate: Option[X509Certificate], keyPair: KeyPair, signatureAlgorithm: String) = {
        val issuerCertificate = suppliedCertificate.getOrElse(buildRootCertificate(keyPair, signatureAlgorithm))
        val certificateBuilder = CertificateBuilder.buildClientCertificate(issuerCertificate, clientSubject, Some(clientAlias), notBefore, notAfter, keyPair.getPublic)
        CertificateBuilder.signCertificate(certificateBuilder, signatureAlgorithm, keyPair.getPrivate)
      }
    }
  }
}