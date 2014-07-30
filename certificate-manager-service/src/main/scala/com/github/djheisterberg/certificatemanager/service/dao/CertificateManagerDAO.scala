import java.sql.Timestamp

import scala.concurrent.Future

import com.github.djheisterberg.fruhling.db.DAO

package com.github.djheisterberg.certificatemanager.service.dao {

  trait CertificateManagerDAO extends DAO {
    import profile.simple._

    type CertInfo = (String, String, String, Timestamp, Timestamp)

    class CertificateTable(tag: Tag) extends Table[CertificateEntity](tag, "CERTIFICATE") {
      def alias = column[String]("ALIAS", O.PrimaryKey)
      def issuerAlias = column[String]("ISSUER")
      def subject = column[String]("SUBJECT")
      def notBefore = column[Timestamp]("NOT_BEFORE")
      def notAfter = column[Timestamp]("NOT_AFTER")
      def algorithm = column[String]("ALGORITHM")
      def salt = column[String]("SALT")
      def privateKey = column[String]("PRIVATE_KEY")
      def certificate = column[String]("CERTIFICATE")

      def * = (alias, issuerAlias, subject, notBefore, notAfter, algorithm, salt, privateKey, certificate) <> (CertificateEntity.tupled, CertificateEntity.unapply)
    }

    val certificateTable = TableQuery[CertificateTable]

    def createCertificate(certificate: CertificateEntity): Future[Unit]

    def getCertificate(alias: String): Future[Option[CertificateEntity]]

    def getRoots(): Future[Seq[CertInfo]]

    def getIssued(issuerAlias: String): Future[Seq[CertInfo]]

    def deleteCertificate(alias: String): Future[Int]
  }
}
