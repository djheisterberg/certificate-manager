import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Date

import scala.concurrent.Future

package com.github.djheisterberg.certificatemanager {
  package service {

    trait CertificateManagerService {

      def getPrivateKey(alias: String, password: Array[Char]): Future[PrivateKey]

      def getCertificate(alias: String): Future[X509Certificate]

      def getRootInfo(): Future[Seq[CertificateInfo]]

      def getIssuedInfo(alias: String): Future[Seq[CertificateInfo]]

      def createAuthorityCertificate(alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, sigAlgorithm: String, notBefore: Date, notAfter: Date): Future[X509Certificate]

      def createAuthorityCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): Future[X509Certificate]

      def createServerCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): Future[X509Certificate]

      def createClientCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): Future[X509Certificate]
    }
  }
}
