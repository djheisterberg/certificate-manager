package com.github.djheisterberg.certificatemanager.service

class BadPrivateKeyPasswordException(alias: String, message: String, cause: Throwable) extends RuntimeException(message, cause) {

  def this(alias: String) = this(alias, null, null)
  def this(alias: String, message: String) = this(alias, message, null)
  def this(alias: String, cause: Throwable) = this(alias, null, cause)
}