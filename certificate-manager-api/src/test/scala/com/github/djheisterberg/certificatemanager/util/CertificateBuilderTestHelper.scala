import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

import scala.concurrent.duration.DurationInt

package com.github.djheisterberg.certificatemanager {
  package util {

    trait CertificateBuilderTestHelper extends KeyPairGenerationTestHelper {

      protected val year = 365.day.toMillis

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

      protected val digitalSignatureIX = 0
      protected val keyEnciphermentIX = 2
      protected val keyCertSignIX = 5
      protected val keyServerAuthOID = "1.3.6.1.5.5.7.3.1"

      protected def buildRootCertificate(keyPair: KeyPair, signatureAlgorithm: String) = {
        val certificateBuilder = CertificateBuilder.buildRootCertificate(rootSubject, Some(rootAlias), notBefore, notAfter, keyPair.getPublic)
        CertificateBuilder.signCertificate(certificateBuilder, signatureAlgorithm, keyPair.getPrivate)
      }

      protected def buildSignerCertificate(issuerCertificate: X509Certificate, publicKey: PublicKey, privateKey: PrivateKey) = {
        val certificateBuilder = CertificateBuilder.buildSignerCertificate(issuerCertificate, signerSubject, Some(signerAlias), notBefore, notAfter, publicKey)
        CertificateBuilder.signCertificate(certificateBuilder, issuerCertificate.getSigAlgName(), privateKey)

      }
      protected def buildServerCertificate(issuerCertificate: X509Certificate, publicKey: PublicKey, privateKey: PrivateKey) = {
        val certificateBuilder = CertificateBuilder.buildServerCertificate(issuerCertificate, serverSubject, Some(serverAlias), notBefore, notAfter, publicKey)
        CertificateBuilder.signCertificate(certificateBuilder, issuerCertificate.getSigAlgName(), privateKey)
      }

      protected def buildClientCertificate(issuerCertificate: X509Certificate, publicKey: PublicKey, privateKey: PrivateKey) = {
        val certificateBuilder = CertificateBuilder.buildClientCertificate(issuerCertificate, clientSubject, Some(clientAlias), notBefore, notAfter, publicKey)
        CertificateBuilder.signCertificate(certificateBuilder, issuerCertificate.getSigAlgName(), privateKey)
      }
    }
  }
}