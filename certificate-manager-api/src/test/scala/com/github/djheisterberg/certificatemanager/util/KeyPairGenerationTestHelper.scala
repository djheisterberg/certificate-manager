import java.security.KeyPairGenerator

import org.bouncycastle.jce.ECNamedCurveTable

package com.github.djheisterberg.certificatemanager {
  package util {

    trait KeyPairGenerationTestHelper {

      protected val rsaKeyPairGenerator = KeyPairGenerator.getInstance(CryptUtil.rsaAlgorithm)
      rsaKeyPairGenerator.initialize(CryptUtil.rsaKeySize)

      protected val dsaKeyPairGenerator = KeyPairGenerator.getInstance(CryptUtil.dsaAlgorithm)
      dsaKeyPairGenerator.initialize(CryptUtil.dsaKeySize)

      protected val bcCurveSpec = ECNamedCurveTable.getParameterSpec(CryptUtil.ecName)
      protected val ecSpec = CryptUtil.convertBCECSpec(bcCurveSpec)
      protected val ecKeyPairGenerator = KeyPairGenerator.getInstance(CryptUtil.ecAlgorithm)
      ecKeyPairGenerator.initialize(ecSpec)
    }
  }
}
