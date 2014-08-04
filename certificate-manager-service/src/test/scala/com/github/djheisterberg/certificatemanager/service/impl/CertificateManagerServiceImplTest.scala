import java.util.Date
import javax.annotation.Resource

import scala.concurrent.Await
import scala.concurrent.Awaitable
import scala.concurrent.ExecutionContext
import scala.concurrent.duration.Duration
import scala.concurrent.duration.DurationInt

import org.junit.Assert
import org.junit.Before
import org.junit.Test

package com.github.djheisterberg.certificatemanager {
  import service.CertificateManagerService

  package service.impl {

    class CertificateManagerServiceImplTest {

      private implicit val waitTime = 2.second

      private def sync[A](op: Awaitable[A])(implicit d: Duration): A = Await.result(op, d)

      private val certMgrSvc = new CertificateManagerServiceImpl(DummyCertificateManagerDAO, ExecutionContext.global)

      @Test
      def testCertificateManager() {
        val keyAlgorithm = "RSA"
        val keySize = 2048
        val keyParam = Left(keySize)
        val sigAlgorithm = "SHA256withRSA"
        val notBefore = new Date()
        val notAfter = new Date(notBefore.getTime + 365.day.toMillis)
        val subjectBase = "C=US,O=djh,OU=certificate manager,CN="

        val rootAlias = "root"
        val rootPassword = rootAlias.toCharArray
        val rootSubject = subjectBase + rootAlias

        val rootCertificate = sync(certMgrSvc.createRootCertificate(rootAlias, rootPassword, rootSubject, None,
          keyAlgorithm, keyParam, sigAlgorithm, notBefore, notAfter))
        val rootCertificateX = sync(certMgrSvc.getCertificate(rootAlias)).get
        Assert.assertEquals("root certificate", rootCertificate, rootCertificateX)
        val rootPrivateKey = sync(certMgrSvc.getPrivateKey(rootAlias, rootPassword)).get

        val signerAlias = "signer"
        val signerPassword = signerAlias.toCharArray
        val signerSubject = subjectBase + signerAlias

        val signerCertificate = sync(certMgrSvc.createSignerCertificate(rootAlias, rootPassword, signerAlias, signerPassword, signerSubject, None,
          keyAlgorithm, keyParam, notBefore, notAfter))
        val signerCertificateX = sync(certMgrSvc.getCertificate(signerAlias)).get
        Assert.assertEquals("signer certificate", signerCertificate, signerCertificateX)
        val signerPrivateKey = sync(certMgrSvc.getPrivateKey(signerAlias, signerPassword)).get
      }
    }
  }
}
