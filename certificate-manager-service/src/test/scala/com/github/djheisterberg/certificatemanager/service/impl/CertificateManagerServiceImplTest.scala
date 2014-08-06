import java.util.Date
import javax.annotation.Resource

import scala.concurrent.Await
import scala.concurrent.Awaitable
import scala.concurrent.ExecutionContext
import scala.concurrent.duration.Duration
import scala.concurrent.duration.DurationInt
import scala.util.Failure
import scala.util.Success

import org.junit.Assert
import org.junit.Before
import org.junit.Test

package com.github.djheisterberg.certificatemanager {
  import service._

  package service.impl {

    class CertificateManagerServiceImplTest {

      private implicit val waitTime = 2.second

      private def sync[A](op: Awaitable[A])(implicit d: Duration): A = Await.result(op, d)

      private val certMgrSvc = new CertificateManagerServiceImpl(DummyCertificateManagerDAO, ExecutionContext.global)

      private val keyAlgorithm = "RSA"
      private val keySize = 2048
      private val keyParam = Left(keySize)
      private val sigAlgorithm = "SHA256withRSA"
      private val notBefore = new Date()
      private val notAfter = new Date(notBefore.getTime + 365.day.toMillis)
      private val subjectBase = "C=US,O=djh,OU=certificate manager,CN="

      @Before
      def clear() {
        DummyCertificateManagerDAO.clear()
      }

      @Test
      def testCertificateManager() {

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

        val serverAlias = "server"
        val serverPassword = serverAlias.toCharArray
        val serverSubject = subjectBase + serverAlias

        val serverCertificate = sync(certMgrSvc.createServerCertificate(signerAlias, signerPassword, serverAlias, serverPassword, serverSubject, None,
          keyAlgorithm, keyParam, notBefore, notAfter))
        val serverCertificateX = sync(certMgrSvc.getCertificate(serverAlias)).get
        Assert.assertEquals("server certificate", serverCertificate, serverCertificateX)
        val serverPrivateKey = sync(certMgrSvc.getPrivateKey(serverAlias, serverPassword)).get

        val clientAlias = "client"
        val clientPassword = clientAlias.toCharArray
        val clientSubject = subjectBase + clientAlias

        val clientCertificate = sync(certMgrSvc.createServerCertificate(signerAlias, signerPassword, clientAlias, clientPassword, clientSubject, None,
          keyAlgorithm, keyParam, notBefore, notAfter))
        val clientCertificateX = sync(certMgrSvc.getCertificate(clientAlias)).get
        Assert.assertEquals("client certificate", clientCertificate, clientCertificateX)
        val clientPrivateKey = sync(certMgrSvc.getPrivateKey(clientAlias, clientPassword)).get

        val rootInfos = sync(certMgrSvc.getRootInfo())
        Assert.assertEquals("1 root", 1, rootInfos.size)
        val rootInfo = rootInfos.head
        Assert.assertEquals("root alias", rootAlias, rootInfo.alias)

        val rootIssuedInfos = sync(certMgrSvc.getIssuedInfo(rootAlias))
        Assert.assertEquals("1 issued by root", 1, rootIssuedInfos.size)
        val rootIssuedInfo = rootIssuedInfos.head
        Assert.assertEquals("root issued alias", signerAlias, rootIssuedInfo.alias)

        val signerIssuedInfos = sync(certMgrSvc.getIssuedInfo(signerAlias))
        Assert.assertEquals("2 issued by signer", 2, signerIssuedInfos.size)
      }

      @Test
      def testNoCertificate() {
        val noCertificateAlias = "no certificate"
        val noCertificatePassword = noCertificateAlias.toCharArray

        val certificate = sync(certMgrSvc.getCertificate(noCertificateAlias))
        certificate match {
          case Some(_) => Assert.fail("Expected certificate = None for no certificate")
          case None => ()
        }

        val privateKey = sync(certMgrSvc.getPrivateKey(noCertificateAlias, noCertificatePassword))
        privateKey match {
          case Some(_) => Assert.fail("Expected private key = None for no certificate")
          case None => ();
        }
      }

      @Test(expected = classOf[BadPrivateKeyPasswordException])
      def testBadPassword() {
        val badRootAlias = "bad root"
        val badRootPassword = badRootAlias.toCharArray
        val notBadRootPassword = ("x" + badRootAlias).toCharArray
        val badRootSubject = subjectBase + badRootAlias

        sync(certMgrSvc.createRootCertificate(badRootAlias, badRootPassword, badRootSubject, None,
          keyAlgorithm, keyParam, sigAlgorithm, notBefore, notAfter))
        sync(certMgrSvc.getPrivateKey(badRootAlias, notBadRootPassword))
      }

      @Test(expected = classOf[NoIssuerException])
      def testNoIssuer() {
        val issuerAlias = "no issuer"
        val issuerPassword = issuerAlias.toCharArray

        val endAlias = "end"
        val endPassword = endAlias.toCharArray
        val endSubject = subjectBase + endAlias

        sync(certMgrSvc.createServerCertificate(issuerAlias, issuerPassword, endAlias, endPassword, endSubject, None,
          keyAlgorithm, keyParam, notBefore, notAfter))
        Assert.fail("no issuer, expected NoIssuerException")
      }
    }
  }
}
