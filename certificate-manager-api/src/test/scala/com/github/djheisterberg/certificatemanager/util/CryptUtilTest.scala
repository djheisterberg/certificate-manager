import java.security.KeyPairGenerator
import java.util.Arrays

import org.bouncycastle.jce.ECNamedCurveTable
import org.junit.Assert
import org.junit.Test

package com.github.djheisterberg.certificatemanager {
  package util {

    class CryptUtilTest extends KeyPairGenerationTestHelper {

      val password = "password".toCharArray
      val salt = "saltsalt".getBytes("UTF-8")

      @Test
      def testEncryptRSAPrivateKey() {
        testEncryptPrivateKey(rsaKeyPairGenerator)
      }

      @Test
      def testEncryptDSAPrivateKey() {
        testEncryptPrivateKey(dsaKeyPairGenerator)
      }

      @Test
      def testEncryptedECPrivateKey() {
        testEncryptPrivateKey(ecKeyPairGenerator)
      }

      @Test
      def testExportRSAPrivateKey() {
        testExportPrivateKey(rsaKeyPairGenerator)
      }

      @Test
      def testExportDSAPrivateKey() {
        testExportPrivateKey(dsaKeyPairGenerator)
      }

      @Test
      def testExportECPrivateKey() {
        testExportPrivateKey(ecKeyPairGenerator)
      }

      @Test
      def testDecodeRSAPublicKey() {
        testDecodePublicKey(rsaKeyPairGenerator)
      }

      @Test
      def testDecodeDSAPublicKey() {
        testDecodePublicKey(dsaKeyPairGenerator)
      }

      @Test
      def testDecodeECPublicKey() {
        testDecodePublicKey(ecKeyPairGenerator)
      }

      @Test
      def testLinedBase64() {
        val n = 100
        val bytes = new Array[Byte](n)
        for (i <- 0 until n) bytes(i) = i.asInstanceOf[Byte]
        val base64String = CryptUtil.encodeBase64(bytes, true)
        Assert.assertTrue("lined bas64 has newline", base64String.contains("\n"))
        val bytesX = CryptUtil.decodeBase64(base64String)
        Assert.assertTrue("base64", Arrays.equals(bytes, bytesX))
      }

      @Test
      def testECF2mConvert() {
        val ec2Name = "SECT283K1"
        val bc2CurveSpec = ECNamedCurveTable.getParameterSpec(ec2Name)
        val ec2Spec = CryptUtil.convertBCECSpec(bc2CurveSpec)
      }

      private def testEncryptPrivateKey(keyPairGenerator: KeyPairGenerator) {
        val algorithm = keyPairGenerator.getAlgorithm
        val privateKey = keyPairGenerator.generateKeyPair().getPrivate
        val encryptedPrivateKey = CryptUtil.encryptPrivateKey(password, salt, privateKey)
        val privateKeyX = CryptUtil.decryptPrivateKey(password, salt, algorithm, encryptedPrivateKey)
        Assert.assertEquals(s"encrypted $algorithm private key", privateKey, privateKeyX)
      }

      private def testExportPrivateKey(keyPairGenerator: KeyPairGenerator) {
        val algorithm = keyPairGenerator.getAlgorithm
        val privateKey = keyPairGenerator.generateKeyPair().getPrivate
        val encryptedPrivateKeyInfo = CryptUtil.encryptExportablePrivateKey(password, privateKey)
        val privateKeyX = CryptUtil.decryptExportablePrivateKey(password, algorithm, encryptedPrivateKeyInfo)
        Assert.assertEquals(s"exported $algorithm private key", privateKey, privateKeyX)
      }

      private def testDecodePublicKey(keyPairGenerator: KeyPairGenerator) {
        val algorithm = keyPairGenerator.getAlgorithm
        val publicKey = keyPairGenerator.generateKeyPair().getPublic
        val publicKeyEncoded = CryptUtil.encodeBase64(publicKey.getEncoded, false)
        val publicKeyX = CryptUtil.decodePublicKey(algorithm, publicKeyEncoded)
        Assert.assertEquals(s"encoded $algorithm public key", publicKey, publicKeyX)
      }
    }
  }
}
