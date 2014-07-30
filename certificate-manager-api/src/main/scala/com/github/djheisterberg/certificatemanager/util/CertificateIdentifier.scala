import java.math.BigInteger
import java.security.PublicKey
import java.util.UUID

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils

package com.github.djheisterberg.certificatemanager {
  package util {

    object CertificateIdentifier {
      val keyIdentifierCreator = new JcaX509ExtensionUtils

      def generateSerialNumber(): BigInteger = {
        val uuid = UUID.randomUUID()
        val lower = BigInteger.valueOf(uuid.getLeastSignificantBits())
        val upper = BigInteger.valueOf(uuid.getMostSignificantBits())
        upper.shiftLeft(64).or(lower)
      }

      def generateSubjectKeyIdentifier(publicKey: PublicKey): SubjectKeyIdentifier = {
        keyIdentifierCreator.createSubjectKeyIdentifier(publicKey)
      }

      def generateAuthorityKeyIdentifier(publicKey: PublicKey) = {
        keyIdentifierCreator.createAuthorityKeyIdentifier(publicKey)
      }
    }
  }
}
