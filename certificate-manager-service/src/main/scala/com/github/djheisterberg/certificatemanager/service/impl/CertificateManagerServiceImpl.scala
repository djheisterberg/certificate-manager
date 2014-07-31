import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Date

import scala.concurrent.Future

package com.github.djheisterberg.certificatemanager {

  import service.CertificateInfo
  import service.CertificateManagerService
  import util.CertificateBuilder

  import service.dao.CertificateManagerDAO

  package service.impl {

    class CertificateManagerServiceImpl(dao: CertificateManagerDAO) extends CertificateManagerService {

      override def getPrivateKey(alias: String, password: Array[Char]): Future[PrivateKey] = ???

      override def getCertificate(alias: String): Future[X509Certificate] = ???

      override def getRootInfo(): Future[Seq[CertificateInfo]] = ???

      override def getIssuedInfo(alias: String): Future[Seq[CertificateInfo]] = ???

      override def createAuthorityCertificate(alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, sigAlgorithm: String, notBefore: Date, notAfter: Date): Future[X509Certificate] = ???

      override def createAuthorityCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): Future[X509Certificate] = ???

      override def createServerCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): Future[X509Certificate] = ???

      override def createClientCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keySize: Int, notBefore: Date, notAfter: Date): Future[X509Certificate] = ???
    }
  }
}
