import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

import org.junit.Assert
import org.junit.Test

package com.github.djheisterberg.certificatemanager {
  package util {

    class CertificateBuilderTest extends CertificateBuilderTestHelper {

      val rootKeyPair = rsaKeyPairGenerator.generateKeyPair()
      val rootCertificate = buildRootCertificate(rootKeyPair, CryptUtil.rsaSignatureAlgorithm)

      @Test
      def testRootCertificateRSA() {
        testRootCertificate(rsaKeyPairGenerator, CryptUtil.rsaSignatureAlgorithm)
      }

      @Test
      def testRootCertificateDSA() {
        testRootCertificate(dsaKeyPairGenerator, CryptUtil.dsaSignatureAlgorithm)
      }

      @Test
      def testRootCertificateEC() {
        testRootCertificate(ecKeyPairGenerator, CryptUtil.ecSignatureAlgorithm)
      }

      private def testRootCertificate(keyPairGenerator: KeyPairGenerator, signatureAlgorithm: String) {
        val keyPair = keyPairGenerator.generateKeyPair()
        val rootCertificate = buildRootCertificate(keyPair, signatureAlgorithm)
        verifyCertificate(rootCertificate, rootSubject, rootSubject, rootAlias, true, false)
      }

      @Test
      def testSignerCertificate() {
        val keyPair = rsaKeyPairGenerator.generateKeyPair()
        val signerCertificate = buildSignerCertificate(rootCertificate, keyPair.getPublic, rootKeyPair.getPrivate)
        verifyCertificate(signerCertificate, rootSubject, signerSubject, signerAlias, true, false)
      }

      @Test
      def testServerCertificate() {
        val keyPair = rsaKeyPairGenerator.generateKeyPair()
        val serverCertificate = buildServerCertificate(rootCertificate, keyPair.getPublic, rootKeyPair.getPrivate)
        verifyCertificate(serverCertificate, rootSubject, serverSubject, serverAlias, false, true)
      }

      @Test
      def testClientCertificate() {
        val keyPair = rsaKeyPairGenerator.generateKeyPair()
        val clientCertificate = buildClientCertificate(rootCertificate, keyPair.getPublic, rootKeyPair.getPrivate)
        verifyCertificate(clientCertificate, rootSubject, clientSubject, clientAlias, false, false)
      }

      private def verifyCertificate(certificate: X509Certificate, issuer: X500Principal, subject: X500Principal, alternativeName: String, signer: Boolean, server: Boolean) {
        certificate.checkValidity()
        Assert.assertEquals("issuer", issuer, certificate.getIssuerX500Principal)
        Assert.assertEquals("subject", subject, certificate.getSubjectX500Principal)
        val _alternativeNames = certificate.getSubjectAlternativeNames
        Assert.assertEquals("#alternative names", 1, _alternativeNames.size)
        val _alternativeNameList = _alternativeNames.iterator().next()
        val _alternativeName = _alternativeNameList.get(1).asInstanceOf[String]
        Assert.assertEquals("alternative name", alternativeName, _alternativeName)
        Assert.assertEquals("not before", notBefore, certificate.getNotBefore)
        Assert.assertEquals("not after", notAfter, certificate.getNotAfter)

        if (signer) {
          Assert.assertTrue("basic constraints", certificate.getBasicConstraints >= 0)
        } else {
          Assert.assertEquals("basic constraints", -1, certificate.getBasicConstraints)
        }

        val keyUsage = certificate.getKeyUsage
        Assert.assertTrue("digitalSignature", keyUsage(digitalSignatureIX))
        Assert.assertTrue("keyEncipherment", keyUsage(keyEnciphermentIX))
        Assert.assertEquals("keyCertSign", signer, keyUsage(keyCertSignIX))

        val extendedKeyUsages = certificate.getExtendedKeyUsage
        if (server) {
          Assert.assertTrue("keyServerAuth", (extendedKeyUsages != null) && extendedKeyUsages.contains(keyServerAuthOID))
        } else {
          Assert.assertTrue("keyServerAuth", (extendedKeyUsages == null) || !extendedKeyUsages.contains(keyServerAuthOID))
        }
      }
    }
  }
}
