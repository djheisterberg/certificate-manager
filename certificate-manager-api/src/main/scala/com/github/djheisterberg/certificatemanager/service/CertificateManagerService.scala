import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Date

package com.github.djheisterberg.certificatemanager {
  package service {

    trait CertificateManagerService {

      def getPrivateKey(alias: String, password: Array[Char]): PrivateKey

      def getCertificate(alias: String): X509Certificate

      def getAuthorityCertificateAliases(): Seq[String]

      def getEndCertificateAliases(alias: String): Seq[String]

      def createAuthorityCertificate(alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, sigAlgorithm: String, notBefore: Date, notAfter: Date): X509Certificate

      def createAuthorityCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): X509Certificate

      def createServerCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): X509Certificate

      def createClientCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): X509Certificate
    }
  }
}
