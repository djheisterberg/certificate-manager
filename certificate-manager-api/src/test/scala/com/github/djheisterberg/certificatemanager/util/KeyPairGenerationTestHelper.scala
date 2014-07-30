import java.security.KeyPairGenerator

import org.bouncycastle.jce.ECNamedCurveTable

package com.github.djheisterberg.certificatemanager {
  package util {

    trait KeyPairGenerationTestHelper {

      protected val rsaAlgorithm = "RSA"
      protected val rsaKeySize = 2048
      protected val dsaAlgorithm = "DSA"
      protected val dsaKeySize = 1024
      protected val ecAlgorithm = "EC"
      protected val ecName = "SECP256R1"

      protected val rsaKeyPairGenerator = KeyPairGenerator.getInstance(rsaAlgorithm)
      rsaKeyPairGenerator.initialize(rsaKeySize)

      protected val dsaKeyPairGenerator = KeyPairGenerator.getInstance(dsaAlgorithm)
      dsaKeyPairGenerator.initialize(dsaKeySize)

      protected val bcCurveSpec = ECNamedCurveTable.getParameterSpec(ecName)
      protected val ecSpec = CryptUtil.convertBCECSpec(bcCurveSpec)
      protected val ecKeyPairGenerator = KeyPairGenerator.getInstance(ecAlgorithm)
      ecKeyPairGenerator.initialize(ecSpec)
    }
  }
}
