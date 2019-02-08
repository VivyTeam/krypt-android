package com.vivy.e2e

import com.vivy.e2e.E2EEncryption.Encrypted
import com.vivy.support.Base64Encoder
import com.vivy.support.KeyConverter
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class EHREncryptionContractTest {
    val privateKeyString = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "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\n" +
        "-----END RSA PRIVATE KEY-----"

    @Test
    fun decryptionGCMTest() {
        val gcmCipherKey = "eU6KAdHtFUtw0XO6ANfKowU9SaLxFx3ocGMfemTj99nFFm6qB1ChFPQUFL3lYTffqRPI+ogeth5TBDg6xe1zoSUDC80gq5t19a1vKxUsjsKAehX2XzH+L/gs6qIis8wlhEp1FLGY5h6sJDp7JtsRG77GjnTBAlUq9tWA2AI6vt6aWggYOYZTbNV8N+qVNlocy64eGGzxqsEdrnctVxzR+sYikrjmAPk0FoakIqKvu+lu4VMW/Pf76o0qn6Z2dPX6Y4uDXpeFjTM0LOWgP0ZhKLmvFRfLfgnMsDTCnBODJD4oxTQkoQOLo2rW/X2E2VU8ymAjBZybaSBvztcYRNYAIzSLdedX79lQSpA7ZLi139ae05UiecUrNAn5VCfl3sFgqLv6Lf0UmeY0/mOdLfkEKYCBisn5dQNArxp0yu+vWRa+May/Czla3aaLRZIq8gFMNJlJ395cuodWE0MaFOkiXCThwt37y04NJn+13coytsvCNsKdWxnIS2X5FSgmhDKq7E3b07/FKdmj6m6Uc3Z73kRIJpQRIseJo5OSBDHioByNcdJ/RzTCnYuHLHc0fbN17Zt5O9oZzoCtLVbzKeqxYxX+WOok6D78lD6lySHcC0plqRpFcI5YBa5dRT7shrzY0I6w0FR3Z5ADWJ9YDlxedCGsDlmFFl3gv4PoUd9psFk="

        val gcmEncryptedMessage = "8ISiEz9Gc8VWjBM3YuvOGeXIA7PXygu79HSKDxIRFxsibKAbgCYRSBPDlFVK6m7hMO0="

        val decrypted = EHREncryption().decrypt(
            KeyConverter().PKC1ToPKCS8PrivateKey(privateKeyString),
            Encrypted(Base64Encoder.debase64(gcmEncryptedMessage), gcmCipherKey, RsaEcbOeapSha256AesGcmNoPadding.VERSION)
        )
        assertThat(String(decrypted,Charsets.UTF_8))
            .isEqualTo("A Healthier Life is a Happier Life")
    }

    @Test
    fun decryptionCBCTest() {
        val cbcCipherKey = "lfZ9jtcOAp7ICnnJvnwnmjejAE5Dneqplt2Rr718YiUmOtFy1mhrEcT3V+L/PryRmRF2QzAVj8F+sUl0XFtBid/vNzE+cNZtmzafs7TKoB8JxlA72DuJDVs7HjmLOHI7mIvY8du+82/KH434sZwhU80RJ3SBKGUcSyV8BuF5sZKL0WME29v0sYWxYrgnh7T29imF6pcEeDaqpZ0FpxodtF3FPIskR7EUNa5VpJoVFHplpaDiPEJRXi1+OGrEzr4ZQgP5ksRwUYU6DONH/eD8mKeJUbUzlEFm8GnoHLTNQfe94WLQKkvLIwUAle0tHehfngMRPNKt/fRnZOMzRHaMGmxcDW383+gWdu6dBuXILP3EAgom17eUffSFlMIWiwVUAjvHUrmwKVHnZL6lsfgdom3aQvJFzOzw0Ya4Y4gGAxgEmjYO28FZidWjPXmSh5nZwTo9p5nOEG9t2ZG8/pxEuJ+S4t5ieQEoKM7WcpVyd0L3PTZOi8doeqbCkV/x2w8QL/jiCpbVWiFB0miBRdWoaOAdBcb+yVLEr/AsBJrdOykWCjFdHCRIHU4iE97HTanGK6+baAVsEHGBuZwxlyIkUJT9OdDxrl9G2+KwhK9fYAh7dYoDxw8yMpPTu40mpnObzJYO0rftGyv/S+b3/XJmHMdCY8qKJLSOEFUmPa/lVyY="

        val cbcEncryptedData = "kbff15ggQQzfKe7atY7oTg+5zTJAZ+oM/yyDv0ocbcisH2YqZTPZx0Oc8bkeC00s"

        val decrypted = EHREncryption().decrypt(
            KeyConverter().PKC1ToPKCS8PrivateKey(privateKeyString),
            Encrypted(Base64Encoder.debase64(cbcEncryptedData), cbcCipherKey, RsaEcbPkcs1AesCbcPkcs7.VERSION)
        )

        assertThat(String(decrypted,Charsets.UTF_8))
            .isEqualTo("A Healthier Life is a Happier Life")
    }
}