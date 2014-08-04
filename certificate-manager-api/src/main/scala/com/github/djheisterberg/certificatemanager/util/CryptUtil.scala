import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECFieldF2m
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

import org.apache.commons.codec.binary.Base64
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder

package com.github.djheisterberg.certificatemanager {
  package util {

    object CryptUtil {

      val rsaAlgorithm = "RSA"
      val rsaKeySize = 2048
      val dsaAlgorithm = "DSA"
      val dsaKeySize = 1024
      val ecAlgorithm = "EC"
      val ecName = "SECP256R1"

      val rsaSignatureAlgorithm = "SHA256withRSA"
      val dsaSignatureAlgorithm = "SHA1withDSA"
      val ecSignatureAlgorithm = "SHA256withECDSA"

      private val passwordHashAlgorithm = "SHA-256"
      private val cipherType = "AES"
      private val cipherMode = "CBC"
      private val cipherPadding = "PKCS5Padding"
      private val cipherAlgorithm = s"$cipherType/$cipherMode/$cipherPadding"
      private val keyIterations = 10000
      private val exportCipherType = JceOpenSSLPKCS8EncryptorBuilder.PBE_SHA1_3DES
      private val exportCipherTypeOID = new ASN1ObjectIdentifier(exportCipherType)
      private val encoding = "UTF-8"

      private val random = new SecureRandom

      val certificateFactory = CertificateFactory.getInstance("X.509")

      def encryptPrivateKey(password: Array[Char], salt: Array[Byte], privateKey: PrivateKey): String = {
        val secretKey = generateSecretKey(password, salt)
        val cipher = Cipher.getInstance(cipherAlgorithm)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.getIV
        val encrypted = cipher.doFinal(privateKey.getEncoded)
        val ivEncrypted = Array.concat(iv, encrypted)
        encodeBase64(ivEncrypted, false)
      }

      def decryptPrivateKey(password: Array[Char], salt: Array[Byte], algorithm: String, privateKeyString: String): PrivateKey = {
        val secretKey = generateSecretKey(password, salt)
        val cipher = Cipher.getInstance(cipherAlgorithm)
        val blockSize = cipher.getBlockSize
        val ivEncrypted = decodeBase64(privateKeyString)
        val ivSpec = new IvParameterSpec(ivEncrypted, 0, blockSize)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        val encoded = cipher.doFinal(ivEncrypted, blockSize, ivEncrypted.length - blockSize)
        val keySpec = new PKCS8EncodedKeySpec(encoded)
        val keyFactory = KeyFactory.getInstance(algorithm)
        keyFactory.generatePrivate(keySpec)
      }

      def encryptExportablePrivateKey(password: Array[Char], privateKey: PrivateKey): PKCS8EncryptedPrivateKeyInfo = {
        val encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(exportCipherTypeOID)
        encryptorBuilder.setIterationCount(keyIterations).setPasssword(password).setRandom(random)
        val encryptedPrivateKeyInfoBuilder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey)
        encryptedPrivateKeyInfoBuilder.build(encryptorBuilder.build())
      }

      def decryptExportablePrivateKey(password: Array[Char], algorithm: String, encryptedPrivateKeyInfo: PKCS8EncryptedPrivateKeyInfo): PrivateKey = {
        val decryptorBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder
        val inputDecryptor = decryptorBuilder.build(password)
        val privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptor)
        val encoded = privateKeyInfo.getEncoded
        val keySpec = new PKCS8EncodedKeySpec(encoded)
        val keyFactory = KeyFactory.getInstance(algorithm)
        keyFactory.generatePrivate(keySpec)
      }

      def decodePublicKey(algorithm: String, publicKeyString: String): PublicKey = {
        val keySpec = new X509EncodedKeySpec(decodeBase64(publicKeyString))
        val keyFactory = KeyFactory.getInstance(algorithm)
        keyFactory.generatePublic(keySpec)
      }

      def encodeCertificate(certificate: X509Certificate): String = encodeBase64(certificate.getEncoded, false)

      def decodeCertificate(certificateString: String): X509Certificate =
        certificateFactory.generateCertificate(new ByteArrayInputStream(decodeBase64(certificateString))).asInstanceOf[X509Certificate]

      def generateSecretKey(password: Array[Char], salt: Array[Byte]): SecretKeySpec = {
        val keyGenerator = new PKCS5S2ParametersGenerator(new SHA256Digest())
        val passwordBytes = new Array[Byte](2 * password.length)
        ByteBuffer.wrap(passwordBytes).asCharBuffer.put(password)
        keyGenerator.init(passwordBytes, salt, keyIterations)
        val key = keyGenerator.generateDerivedParameters(256).asInstanceOf[KeyParameter].getKey()
        new SecretKeySpec(key, cipherType)
      }

      def encodeBase64(bytes: Array[Byte], lines: Boolean): String = new String(Base64.encodeBase64(bytes, lines), encoding)

      def decodeBase64(s: String): Array[Byte] = Base64.decodeBase64(s.getBytes(encoding))

      def convertBCECSpec(bcCurveSpec: org.bouncycastle.jce.spec.ECParameterSpec): ECParameterSpec = {
        val bcCurve = bcCurveSpec.getCurve
        val ecA = bcCurve.getA.toBigInteger
        val ecB = bcCurve.getB.toBigInteger
        val ecField =
          bcCurve match {
            case bcCurveFp: ECCurve.Fp => {
              new ECFieldFp(bcCurveFp.getQ)
            }
            case bcCurveF2m: ECCurve.F2m =>
              {
                val m = bcCurveF2m.getM
                val k1 = bcCurveF2m.getK1
                val k2 = bcCurveF2m.getK2
                val k3 = bcCurveF2m.getK3
                if (k1 == 0) {
                  new ECFieldF2m(m)
                } else if (k3 == 0) {
                  new ECFieldF2m(m, Array(k1))
                } else {
                  new ECFieldF2m(m, Array(k3, k2, k1))
                }
              }
          }
        val curve = new EllipticCurve(ecField, ecA, ecB)
        val bcG = bcCurveSpec.getG
        val ecG = new ECPoint(bcG.getX.toBigInteger, bcG.getY.toBigInteger)
        val ecN = bcCurveSpec.getN
        val ecH = bcCurveSpec.getH.intValue
        new ECParameterSpec(curve, ecG, ecN, ecH)
      }
    }
  }
}
