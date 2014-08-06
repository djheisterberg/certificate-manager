package com.github.djheisterberg.certificatemanager.service

class NoIssuerException(val issuer: String, message: String, cause: Throwable) extends RuntimeException(message, cause) {

  def this(issuer: String) = this(issuer, null, null)
  def this(issuer: String, message: String) = this(issuer, message, null)
  def this(issuer: String, cause: Throwable) = this(issuer, null, cause)
}