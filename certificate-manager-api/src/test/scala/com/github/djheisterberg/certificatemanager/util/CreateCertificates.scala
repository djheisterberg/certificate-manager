import java.io.FileOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

import scala.concurrent.duration.DurationInt

package com.github.djheisterberg.certificatemanager.util {

  object CreateCertificates {
    val year = 365.days.toMillis

    def main(args: Array[String]) {

      val rootKeyStorePath = "root.jks"
      val serverKeyStorePath = "server.jks"
      val clientKeyStorePath = "client.jks"
      val password = "changeit".toCharArray

      val signatureAlgorithm = "SHA1withRSA"

      val rootSubject = new X500Principal("CN=Certificate Authority, C=US")
      val serverSubject = new X500Principal("CN=Server, C=US")
      val clientSubject = new X500Principal("CN=Client, C=US")
      val notBefore = new Date
      val notAfter = new Date(notBefore.getTime + year)
      val rootAlias = "CA"
      val rootAlternativeName = Some(rootAlias)
      val serverAlias = "Server"
      val serverAlternativeName = Some(serverAlias)
      val clientAlias = "Client"
      val clientAlternativeName = Some(clientAlias)

      val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
      keyPairGenerator.initialize(2048)

      val rootKeyPair = keyPairGenerator.generateKeyPair()
      val rootPrivateKey = rootKeyPair.getPrivate
      val rootPublicKey = rootKeyPair.getPublic

      val rootCertificateBuilder = CertificateBuilder.buildRootCertificate(rootSubject, rootAlternativeName, notBefore, notAfter, rootPublicKey)
      val rootCertificate = CertificateBuilder.signCertificate(rootCertificateBuilder, signatureAlgorithm, rootPrivateKey)

      val rootKeyStore = KeyStore.getInstance(KeyStore.getDefaultType)
      rootKeyStore.load(null, null)
      rootKeyStore.setCertificateEntry(rootAlias, rootCertificate)
      val rootKeyStoreStream = new FileOutputStream(rootKeyStorePath)
      rootKeyStore.store(rootKeyStoreStream, password)
      rootKeyStoreStream.close

      println("rootCertificate")
      println(rootCertificate)
      println

      val serverKeyPair = keyPairGenerator.generateKeyPair()
      val serverPrivateKey = serverKeyPair.getPrivate
      val serverPublicKey = serverKeyPair.getPublic

      val serverCertificateBuilder = CertificateBuilder.buildServerCertificate(rootCertificate, serverSubject, serverAlternativeName, notBefore, notAfter, serverPublicKey)
      val serverCertificate = CertificateBuilder.signCertificate(serverCertificateBuilder, signatureAlgorithm, rootPrivateKey)

      val serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType)
      serverKeyStore.load(null, null)
      serverKeyStore.setKeyEntry(serverAlias, serverPrivateKey, password, Array[Certificate](serverCertificate))
      val serverKeyStoreStream = new FileOutputStream(serverKeyStorePath)
      serverKeyStore.store(serverKeyStoreStream, password)
      serverKeyStoreStream.close

      println("serverCertificate")
      println(serverCertificate)
      println

      val clientKeyPair = keyPairGenerator.generateKeyPair()
      val clientPrivateKey = clientKeyPair.getPrivate
      val clientPublicKey = clientKeyPair.getPublic

      val clientCertificateBuilder = CertificateBuilder.buildClientCertificate(rootCertificate, clientSubject, clientAlternativeName, notBefore, notAfter, clientPublicKey)
      val clientCertificate = CertificateBuilder.signCertificate(clientCertificateBuilder, signatureAlgorithm, rootPrivateKey)

      val clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType)
      clientKeyStore.load(null, null)
      clientKeyStore.setKeyEntry(clientAlias, clientPrivateKey, password, Array[Certificate](clientCertificate))
      val clientKeyStoreStream = new FileOutputStream(clientKeyStorePath)
      clientKeyStore.store(clientKeyStoreStream, password)
      clientKeyStoreStream.close

      println("clientCertificate")
      println(clientCertificate)
      println

    }
  }
}
