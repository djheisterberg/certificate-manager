import java.sql.SQLException

import scala.collection.mutable.Map
import scala.collection.mutable.Set
import scala.concurrent.Future
import scala.slick.driver.JdbcDriver

package com.github.djheisterberg.certificatemanager.service {
  import dao.CertificateEntity
  import dao.CertificateManagerDAO

  package impl {

    object DummyCertificateManagerDAO extends CertificateManagerDAO {

      override protected val profile: JdbcDriver = null

      import profile.backend.DatabaseDef

      override protected val database: DatabaseDef = null

      val certificatesByAlias = Map[String, CertificateEntity]()

      val certificatesByIssuer = Map[String, Set[CertificateEntity]]()

      def clear() {
        certificatesByAlias.clear()
        certificatesByIssuer.clear()
      }

      override def createCertificate(certificate: CertificateEntity): Future[Unit] = {
        val alias = certificate.alias
        if (certificatesByAlias contains alias) throw new SQLException("PK violation")
        certificatesByAlias += ((alias, certificate))

        val issuerAlias = certificate.issuerAlias
        if (issuerAlias != alias) {
          if (!(certificatesByAlias contains issuerAlias)) throw new SQLException("FK violation")
          (certificatesByIssuer getOrElseUpdate (issuerAlias, Set[CertificateEntity]())) += certificate
        }

        Future.successful()
      }

      override def getCertificate(alias: String): Future[Option[CertificateEntity]] = Future.successful(certificatesByAlias get alias)

      override def getRoots(): Future[Seq[CertificateInfo]] =
        Future.successful((for (c <- certificatesByAlias.values if (c.alias == c.issuerAlias)) yield certificateInfo(c)).toSeq)

      override def getIssued(issuerAlias: String): Future[Seq[CertificateInfo]] = {
        Future.successful(((certificatesByIssuer getOrElse (issuerAlias, Seq.empty)) map certificateInfo).toSeq)
      }

      override def deleteCertificate(alias: String): Future[Int] = ???
    }
  }
}
