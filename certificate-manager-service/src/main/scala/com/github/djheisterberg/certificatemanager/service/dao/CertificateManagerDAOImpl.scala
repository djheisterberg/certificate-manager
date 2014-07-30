import javax.sql.DataSource

import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.slick.driver.JdbcProfile
import scala.slick.jdbc.StaticQuery
import scala.slick.jdbc.StaticQuery.interpolation

package com.github.djheisterberg.certificatemanager.service.dao {

  class CertificateManagerDAOImpl(dataSource: DataSource, override protected val profile: JdbcProfile, implicit private val executionContext: ExecutionContext) extends CertificateManagerDAO {

    import profile.simple._

    override protected val database = Database.forDataSource(dataSource)

    private def certInfo(c: CertificateTable) = (c.alias, c.issuerAlias, c.subject, c.notBefore, c.notAfter)

    override def createCertificate(certificate: CertificateEntity): Future[Unit] =
      futureInTransaction { implicit session => certificateTable += certificate }

    override def getCertificate(alias: String): Future[Option[CertificateEntity]] =
      futureInSession { implicit session => certificateTable.filter(_.alias === alias).firstOption }

    override def deleteCertificate(alias: String): Future[Int] =
      futureInTransaction { implicit session => certificateTable.filter(_.alias === alias).delete }

    override def getRoots(): Future[Seq[CertInfo]] =
      futureInSession { implicit session => certificateTable.filter(c => c.issuerAlias === c.alias).map(certInfo).run }

    override def getIssued(issuerAlias: String): Future[Seq[CertInfo]] =
      futureInSession { implicit session =>
        certificateTable.filter(c => (c.issuerAlias === issuerAlias) && (c.issuerAlias =!= c.alias)).map(certInfo).run
      }
  }
}
