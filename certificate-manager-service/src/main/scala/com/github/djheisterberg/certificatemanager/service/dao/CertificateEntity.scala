import java.sql.Timestamp

package com.github.djheisterberg.certificatemanager.service.dao {
  case class CertificateEntity(
    alias: String,
    issuerAlias: String,
    subject: String,
    notBefore: Timestamp,
    notAfter: Timestamp,
    algorithm: String,
    salt: String,
    privateKey: String,
    certificate: String)
}