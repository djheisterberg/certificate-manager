import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.util.Date
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

package com.github.djheisterberg.certificatemanager {
  package util {

    object CertificateBuilder {

      val signerBasicConstraints = new BasicConstraints(true)
      val endBasicConstraints = new BasicConstraints(false)
      val signerKeyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyCertSign)
      val endKeyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
      val serverExtendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)

      def buildRootCertificate(subject: X500Principal, alternativeName: Option[String], notBefore: Date, notAfter: Date, publicKey: PublicKey): JcaX509v3CertificateBuilder = {
        val serialNumber = CertificateIdentifier.generateSerialNumber()

        val certificateBuilder = new JcaX509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, publicKey)

        finishSignerCertificate(certificateBuilder, alternativeName, publicKey)
      }

      def buildSignerCertificate(issuer: X509Certificate, subject: X500Principal, alternativeName: Option[String], notBefore: Date, notAfter: Date, publicKey: PublicKey): JcaX509v3CertificateBuilder = {
        val serialNumber = CertificateIdentifier.generateSerialNumber()

        val certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKey)

        finishSignerCertificate(certificateBuilder, alternativeName, publicKey)
      }

      def finishSignerCertificate(certificateBuilder: JcaX509v3CertificateBuilder, alternativeName: Option[String], publicKey: PublicKey): JcaX509v3CertificateBuilder = {
        addExtensions(certificateBuilder, true, false, alternativeName)
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, CertificateIdentifier.generateSubjectKeyIdentifier(publicKey))

        certificateBuilder
      }

      def buildServerCertificate(issuer: X509Certificate, subject: X500Principal, alternativeName: Option[String], notBefore: Date, notAfter: Date, publicKey: PublicKey): JcaX509v3CertificateBuilder = {
        buildEndCertificate(true, issuer, subject, alternativeName, notBefore, notAfter, publicKey)
      }

      def buildClientCertificate(issuer: X509Certificate, subject: X500Principal, alternativeName: Option[String], notBefore: Date, notAfter: Date, publicKey: PublicKey): JcaX509v3CertificateBuilder = {
        buildEndCertificate(false, issuer, subject, alternativeName, notBefore, notAfter, publicKey)
      }

      private def buildEndCertificate(server: Boolean, issuer: X509Certificate, subject: X500Principal, alternativeName: Option[String], notBefore: Date, notAfter: Date, publicKey: PublicKey): JcaX509v3CertificateBuilder = {
        val serialNumber = CertificateIdentifier.generateSerialNumber()

        val certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKey)
        addExtensions(certificateBuilder, false, server, alternativeName)
        certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, CertificateIdentifier.generateAuthorityKeyIdentifier(issuer.getPublicKey))

        certificateBuilder
      }

      def signCertificate(certificateBuilder: X509v3CertificateBuilder, signatureAlgorithm: String, privateKey: PrivateKey): X509Certificate = {
        val signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm)
        val signer = signerBuilder.build(privateKey)

        val certficateHolder = certificateBuilder.build(signer)
        val certificateFactory = CertificateFactory.getInstance("X.509")
        certificateFactory.generateCertificate(new ByteArrayInputStream(certficateHolder.getEncoded)).asInstanceOf[X509Certificate]
      }

      private def addExtensions(certificateBuilder: JcaX509v3CertificateBuilder, signer: Boolean, server: Boolean, alternativeName: Option[String]) {
        if (signer) {
          certificateBuilder.addExtension(Extension.basicConstraints, true, signerBasicConstraints)
          certificateBuilder.addExtension(Extension.keyUsage, true, signerKeyUsage)
        } else {
          certificateBuilder.addExtension(Extension.basicConstraints, true, endBasicConstraints)
          certificateBuilder.addExtension(Extension.keyUsage, true, endKeyUsage)
          if (server) {
            certificateBuilder.addExtension(Extension.extendedKeyUsage, false, serverExtendedKeyUsage)
          }
        }
        alternativeName map { name => certificateBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, name))) }
      }
    }
  }
}
