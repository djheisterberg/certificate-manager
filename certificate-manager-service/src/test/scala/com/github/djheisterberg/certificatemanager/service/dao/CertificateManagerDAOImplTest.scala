import java.sql.Timestamp

import scala.concurrent.Await
import scala.concurrent.Awaitable
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext
import scala.util.Failure
import scala.util.Success

import com.github.djheisterberg.fruhling.db.C3P0DataSourceFactory
import com.github.djheisterberg.fruhling.db.DataSourceOp
import com.github.djheisterberg.fruhling.db.HikariCPDataSourceFactory
import com.github.djheisterberg.fruhling.db.LiquibaseRunner
import com.github.djheisterberg.fruhling.db.SlickProfiler

import com.typesafe.config.ConfigFactory

import org.junit.Assert
import org.junit.Test

package com.github.djheisterberg.certificatemanager.service.dao {

  class CertificateManagerDAOImplTest {

    private val DB_CONFIG_PATH = "certificate_manager_db"
    private val DDL_PATH = "com/github/djheisterberg/certificatemanager/service/dao/certificate-manager-ddl.xml"

    private implicit val waitTime = 2.seconds

    private def sync[A](op: => Awaitable[A])(implicit wait: Duration): A = {
      Await.result(op, wait)
    }

    private def getDAO(): CertificateManagerDAO = {
      val config = ConfigFactory.load()
      val dbConfig = config.getConfig(DB_CONFIG_PATH)
      val dataSource = HikariCPDataSourceFactory(dbConfig)

      val dataSourceOp = new DataSourceOp(dataSource)
      dataSourceOp(LiquibaseRunner(DDL_PATH))
      val profile = dataSourceOp(SlickProfiler.apply).get

      val dao = new CertificateManagerDAOImpl(dataSource, profile, ExecutionContext.global)
      dao
    }

    @Test
    def testCRUD() {
      val dao = getDAO()
      Assert.assertNotNull(dao)

      val authCert = CertificateEntity("authAlias", "authAlias", "authSubject", new Timestamp(System.currentTimeMillis), new Timestamp(Long.MaxValue), "algorithm", "salt", "authPK", "authCert")
      val endCert = CertificateEntity("endAlias", "authAlias", "endSubject", authCert.notBefore, authCert.notAfter, "algorithm", "salt", "endPK", "endCert")

      sync(dao.createCertificate(authCert))
      sync(dao.createCertificate(endCert))

      Assert.assertEquals("auth cert", authCert, sync(dao.getCertificate(authCert.alias)).get)
      Assert.assertEquals("end cert", endCert, sync(dao.getCertificate(endCert.alias)).get)

      val roots = sync(dao.getRoots())
      Assert.assertEquals("1 root", 1, roots.size)
      Assert.assertEquals("root", (authCert.alias, authCert.issuerAlias, authCert.subject, authCert.notBefore, authCert.notAfter), roots.head)

      val issued = sync(dao.getIssued(authCert.alias))
      Assert.assertEquals("1 issued", 1, issued.size)
      Assert.assertEquals("issued", (endCert.alias, endCert.issuerAlias, endCert.subject, endCert.notBefore, endCert.notAfter), issued.head)

      val nDelete = sync(dao.deleteCertificate(authCert.alias))
      Assert.assertEquals("1 delete", 1, nDelete)
      Assert.assertEquals("no auth cert", None, sync(dao.getCertificate(authCert.alias)))
      Assert.assertEquals("no end cert", None, sync(dao.getCertificate(endCert.alias)))
    }
  }
}
