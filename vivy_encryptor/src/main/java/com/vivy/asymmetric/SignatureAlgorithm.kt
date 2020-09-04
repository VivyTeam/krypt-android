/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.vivy.asymmetric

/**
 * Type-safe representation of standard JWT signature algorithm names as defined in the
 * [JSON Web Algorithms](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31) specification.
 *
 * @since 0.1
 *
 * copied from
 * https://github.com/jwtk/jjwt/blob/6b02041be62cb50ad3fcea80e655f7f5fe46f6f8/api/src/main/java/io/jsonwebtoken/SignatureAlgorithm.java
 *
 */
enum class SignatureAlgorithm constructor(
    /**
     * @return the JWA algorithm name constant.
     */
    val value: String,
    /**
     * @return the JWA algorithm description.
     */
    val description: String,
    /**
     * @return Returns the cryptographic family name of the signature algorithm.
     */
    val familyName: String,
    /**
     * @return the name of the JCA algorithm used to compute the signature.
     */
    val jcaName: String
) {
    /**
     * JWA name for `No digital signature or MAC performed`
     */
    NONE(value = "none", description = "No digital signature or MAC performed", familyName = "None", jcaName = ""),

    /**
     * JWA algorithm name for `HMAC using SHA-256`
     */
    HS256(value = "HS256", description = "HMAC using SHA-256", familyName = "HMAC", jcaName = "HmacSHA256"),

    /**
     * JWA algorithm name for `HMAC using SHA-384`
     */
    HS384(value = "HS384", description = "HMAC using SHA-384", familyName = "HMAC", jcaName = "HmacSHA384"),

    /**
     * JWA algorithm name for `HMAC using SHA-512`
     */
    HS512(value = "HS512", description = "HMAC using SHA-512", familyName = "HMAC", jcaName = "HmacSHA512"),

    /**
     * JWA algorithm name for `RSASSA-PKCS-v1_5 using SHA-256`
     */
    RS256(value = "RS256", description = "RSASSA-PKCS-v1_5 using SHA-256", familyName = "RSA", jcaName = "SHA256withRSA"),

    /**
     * JWA algorithm name for `RSASSA-PKCS-v1_5 using SHA-384`
     */
    RS384(value = "RS384", description = "RSASSA-PKCS-v1_5 using SHA-384", familyName = "RSA", jcaName = "SHA384withRSA"),

    /**
     * JWA algorithm name for `RSASSA-PKCS-v1_5 using SHA-512`
     */
    RS512(value = "RS512", description = "RSASSA-PKCS-v1_5 using SHA-512", familyName = "RSA", jcaName = "SHA512withRSA"),

    /**
     * JWA algorithm name for `ECDSA using P-256 and SHA-256`
     */
    ES256(value = "ES256", description = "ECDSA using P-256 and SHA-256", familyName = "ECDSA", jcaName = "SHA256withECDSA"),

    /**
     * JWA algorithm name for `ECDSA using P-384 and SHA-384`
     */
    ES384(value = "ES384", description = "ECDSA using P-384 and SHA-384", familyName = "ECDSA", jcaName = "SHA384withECDSA"),

    /**
     * JWA algorithm name for `ECDSA using P-521 and SHA-512`
     */
    ES512(value = "ES512", description = "ECDSA using P-521 and SHA-512", familyName = "ECDSA", jcaName = "SHA512withECDSA");

    companion object {
        fun getSignatureAlgorithm(type: String): SignatureAlgorithm {
            for (value in values()) {
                if (value.value == type) {
                    return value
                }
            }
            return NONE
        }
    }
}
