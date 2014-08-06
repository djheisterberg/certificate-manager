import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.sql.Timestamp
import java.util.Date

import javax.security.auth.x500.X500Principal

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.ECNamedCurveTable

package com.github.djheisterberg.certificatemanager {

  import service._
  import service.dao.CertificateEntity
  import service.dao.CertificateManagerDAO
  import util.CertificateBuilder
  import util.CryptUtil

  package service.impl {

    class CertificateManagerServiceImpl(dao: CertificateManagerDAO, implicit private val executionContext: ExecutionContext) extends CertificateManagerService {

      case class IssuerInfo(alias: String, certificate: X509Certificate, privateKey: PrivateKey)

      case class SigningInfo(alias: String, subject: X500Principal, sigAlgorithm: String, privateKey: PrivateKey)

      type NonRootCertificateBuilder = (X509Certificate, X500Principal, Option[String], Date, Date, PublicKey) => JcaX509v3CertificateBuilder

      private val random = new SecureRandom

      override def getPrivateKey(alias: String, password: Array[Char]): Future[Option[PrivateKey]] =
        dao.getCertificate(alias) map { _ map recoverPrivateKey(alias, password) }

      override def getCertificate(alias: String): Future[Option[X509Certificate]] =
        dao.getCertificate(alias) map { _ map recoverCertificate }

      override def getRootInfo(): Future[Seq[CertificateInfo]] = dao.getRoots()

      override def getIssuedInfo(issuerAlias: String): Future[Seq[CertificateInfo]] = dao.getIssued(issuerAlias)

      override def createRootCertificate(alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, sigAlgorithm: String, notBefore: Date, notAfter: Date): Future[X509Certificate] = {

        val subjectX500 = new X500Principal(subject)
        val keyPair = generateKeyPair(keyAlgorithm, keyParam)
        val privateKey = keyPair.getPrivate
        val signingInfo = SigningInfo(alias, subjectX500, sigAlgorithm, privateKey)

        val certificateBuilder = CertificateBuilder.buildRootCertificate(subjectX500, alternativeName, notBefore, notAfter, keyPair.getPublic)

        signAndPersist(alias, password, certificateBuilder, privateKey)(signingInfo)
      }

      override def createSignerCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, notBefore: Date, notAfter: Date): Future[X509Certificate] = {

        createNonRootCertificate(CertificateBuilder.buildSignerCertificate, issuerAlias, issuerPassword, alias, password, subject, alternativeName,
          keyAlgorithm, keyParam, notBefore, notAfter)
      }

      override def createServerCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, notBefore: Date, notAfter: Date): Future[X509Certificate] = {

        createNonRootCertificate(CertificateBuilder.buildServerCertificate, issuerAlias, issuerPassword, alias, password, subject, alternativeName,
          keyAlgorithm, keyParam, notBefore, notAfter)
      }

      override def createClientCertificate(issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, notBefore: Date, notAfter: Date): Future[X509Certificate] = {

        createNonRootCertificate(CertificateBuilder.buildClientCertificate, issuerAlias, issuerPassword, alias, password, subject, alternativeName,
          keyAlgorithm, keyParam, notBefore, notAfter)
      }

      private def createNonRootCertificate(builder: NonRootCertificateBuilder, issuerAlias: String, issuerPassword: Array[Char],
        alias: String, password: Array[Char], subject: String, alternativeName: Option[String],
        keyAlgorithm: String, keyParam: KeyParam, notBefore: Date, notAfter: Date): Future[X509Certificate] = {

        val issuerInfo = dao.getCertificate(issuerAlias) map requireIssuerInfo(issuerAlias, issuerPassword)
        val subjectX500 = new X500Principal(subject)
        val keyPair = generateKeyPair(keyAlgorithm, keyParam)

        issuerInfo flatMap createNonRootCertificate(builder, alias, password, subjectX500, alternativeName, keyPair, notBefore, notAfter)
      }

      private def createNonRootCertificate(builder: NonRootCertificateBuilder,
        alias: String, password: Array[Char], subject: X500Principal, alternativeName: Option[String],
        keyPair: KeyPair, notBefore: Date, notAfter: Date)(issuerInfo: IssuerInfo): Future[X509Certificate] = {

        val issuerCertificate = issuerInfo.certificate
        val signingInfo = SigningInfo(issuerInfo.alias, issuerCertificate.getSubjectX500Principal, issuerCertificate.getSigAlgName, issuerInfo.privateKey)

        val certificateBuilder = builder(issuerInfo.certificate, subject, alternativeName, notBefore, notAfter, keyPair.getPublic)

        signAndPersist(alias, password, certificateBuilder, keyPair.getPrivate)(signingInfo)
      }

      private def signAndPersist(alias: String, password: Array[Char], certificateBuilder: JcaX509v3CertificateBuilder, privateKey: PrivateKey)(signingInfo: SigningInfo) = {
        val salt = new Array[Byte](12)
        random.nextBytes(salt)

        val certificate = CertificateBuilder.signCertificate(certificateBuilder, signingInfo.sigAlgorithm, signingInfo.privateKey)

        val subject = certificate.getSubjectX500Principal.getName
        val notBefore = new Timestamp(certificate.getNotBefore.getTime)
        val notAfter = new Timestamp(certificate.getNotAfter.getTime)
        val keyAlgorithm = privateKey.getAlgorithm
        val encodedSalt = CryptUtil.encodeBase64(salt, false)
        val encryptedPrivateKey = CryptUtil.encryptPrivateKey(password, salt, privateKey)
        val encodedCertificate = CryptUtil.encodeCertificate(certificate)

        val certificateEntity = CertificateEntity(alias, signingInfo.alias, subject, notBefore, notAfter, keyAlgorithm, encodedSalt, encryptedPrivateKey, encodedCertificate)
        dao.createCertificate(certificateEntity) map { _ => certificate }
      }

      private def requireIssuerInfo(issuerAlias: String, password: Array[Char])(certificateOption: Option[CertificateEntity]) = {
        certificateOption match {
          case Some(certificateEntity) => {
            val certificate = recoverCertificate(certificateEntity)
            IssuerInfo(issuerAlias, certificate, recoverPrivateKey(issuerAlias, password)(certificateEntity))
          }
          case None => throw new NoIssuerException(issuerAlias, s"No issuer certificate for '${issuerAlias}'")
        }
      }

      private def recoverPrivateKey(alias: String, password: Array[Char])(certificateEntity: CertificateEntity) = {
        val salt = CryptUtil.decodeBase64(certificateEntity.salt)
        val algorithm = certificateEntity.algorithm
        val privateKeyString = certificateEntity.privateKey
        try {
          CryptUtil.decryptPrivateKey(password, salt, algorithm, privateKeyString)
        } catch { case e: Exception => throw new BadPrivateKeyPasswordException(alias, e) }
      }

      private def recoverCertificate(certificateEntity: CertificateEntity) = CryptUtil.decodeCertificate(certificateEntity.certificate)

      private def generateKeyPair(keyAlgorithm: String, keyParam: KeyParam) = {
        val keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm)
        keyParam match {
          case Left(keySize) => keyPairGenerator.initialize(keySize, random)
          case Right(ecName) => keyPairGenerator.initialize(CryptUtil.convertBCECSpec(ECNamedCurveTable.getParameterSpec(ecName)), random)
        }
        keyPairGenerator.generateKeyPair()
      }
    }
  }
}
