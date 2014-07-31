import java.util.Date

package com.github.djheisterberg.certificatemanager.service {
  case class CertificateInfo(alias: String, issuerAlias: String, subject: String, notBefore: Date, notAfter: Date)
}