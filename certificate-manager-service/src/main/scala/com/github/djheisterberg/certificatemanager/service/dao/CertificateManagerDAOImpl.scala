import javax.sql.DataSource

import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.slick.driver.JdbcProfile
import scala.slick.jdbc.StaticQuery
import scala.slick.jdbc.StaticQuery.interpolation

package com.github.djheisterberg.certificatemanager {
  import service.CertificateInfo

  package service.dao {

    class CertificateManagerDAOImpl(dataSource: DataSource, override protected val profile: JdbcProfile, implicit private val executionContext: ExecutionContext) extends CertificateManagerDAO {

      import profile.simple._

      override protected val database = Database.forDataSource(dataSource)

      override def createCertificate(certificate: CertificateEntity): Future[Unit] =
        futureInTransaction { implicit session => certificateTable += certificate }

      override def getCertificate(alias: String): Future[Option[CertificateEntity]] =
        futureInSession { implicit session => certificateTable.filter(_.alias === alias).firstOption }

      override def deleteCertificate(alias: String): Future[Int] =
        futureInTransaction { implicit session => certificateTable.filter(_.alias === alias).delete }

      override def getRoots(): Future[Seq[CertificateInfo]] =
        futureInSession { implicit session =>
          certificateTable.filter(c => c.issuerAlias === c.alias).run map certificateInfo
        }

      override def getIssued(issuerAlias: String): Future[Seq[CertificateInfo]] =
        futureInSession { implicit session =>
          certificateTable.filter(c => (c.issuerAlias === issuerAlias) && (c.issuerAlias =!= c.alias)).run map certificateInfo
        }
    }
  }
}
