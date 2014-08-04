import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Date

import scala.concurrent.Future

package com.github.djheisterberg.certificatemanager {
  package service {

    trait CertificateManagerService {

      type KeyParam = Either[Int, String]

      def getPrivateKey(alias: String, password: Array[Char]): Future[Option[PrivateKey]]

      def getCertificate(alias: String): Future[Option[X509Certificate]]

      def getRootInfo(): Future[Seq[CertificateInfo]]

      def getIssuedInfo(issuerAlias: String): Future[Seq[CertificateInfo]]

      def createRootCertificate(alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, sigAlgorithm: String, notBefore: Date, notAfter: Date): Future[X509Certificate]

      def createSignerCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, notBefore: Date, notAfter: Date): Future[X509Certificate]

      def createServerCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, notBefore: Date, notAfter: Date): Future[X509Certificate]

      def createClientCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, notBefore: Date, notAfter: Date): Future[X509Certificate]
    }
  }
}
