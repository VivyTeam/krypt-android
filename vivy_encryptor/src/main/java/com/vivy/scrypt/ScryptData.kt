package com.vivy.scrypt

data class ScryptData(
  val genSCryptKey: ByteArray,
  val iv: ByteArray,
  val encryptedData: ByteArray
)