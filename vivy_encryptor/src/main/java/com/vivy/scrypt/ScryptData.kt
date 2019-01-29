package com.vivy.scrypt

data class ScryptData(
  val pin: String,
  val salt: String,
  val genSCryptKey: ByteArray,
  val iv: ByteArray,
  val encryptedData: ByteArray
)