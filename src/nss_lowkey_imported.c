/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <lowkeyti.h>
#include <secasn1.h>
#include <secoid.h>

/*
These templates and functions are taken from lib/softoken/lowkey.c in NSS v3.97
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L18-L46
 */
const SEC_ASN1Template nsslowkey_AttributeTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(NSSLOWKEYAttribute) },
    { SEC_ASN1_OBJECT_ID, offsetof(NSSLOWKEYAttribute, attrType) },
    { SEC_ASN1_SET_OF | SEC_ASN1_XTRN,
      offsetof(NSSLOWKEYAttribute, attrValue),
      SEC_ASN1_SUB(SEC_AnyTemplate) },
    { 0 }
};

const SEC_ASN1Template nsslowkey_SetOfAttributeTemplate[] = {
    { SEC_ASN1_SET_OF, 0, nsslowkey_AttributeTemplate },
};
/* ASN1 Templates for new decoder/encoder */
const SEC_ASN1Template nsslowkey_PrivateKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(NSSLOWKEYPrivateKeyInfo) },
    { SEC_ASN1_INTEGER,
      offsetof(NSSLOWKEYPrivateKeyInfo, version) },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN,
      offsetof(NSSLOWKEYPrivateKeyInfo, algorithm),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_OCTET_STRING,
      offsetof(NSSLOWKEYPrivateKeyInfo, privateKey) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | 0,
      offsetof(NSSLOWKEYPrivateKeyInfo, attributes),
      nsslowkey_SetOfAttributeTemplate },
    { 0 }
};

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L65-L71
 */
const SEC_ASN1Template nsslowkey_PQGParamsTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(PQGParams) },
    { SEC_ASN1_INTEGER, offsetof(PQGParams, prime) },
    { SEC_ASN1_INTEGER, offsetof(PQGParams, subPrime) },
    { SEC_ASN1_INTEGER, offsetof(PQGParams, base) },
    { 0 }
};

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L73-L85
 */
const SEC_ASN1Template nsslowkey_RSAPrivateKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(NSSLOWKEYPrivateKey) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.version) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.modulus) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.publicExponent) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.privateExponent) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.prime1) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.prime2) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.exponent1) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.exponent2) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.rsa.coefficient) },
    { 0 }
};

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L94-L96
 */
const SEC_ASN1Template nsslowkey_DSAPrivateKeyExportTemplate[] = {
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.dsa.privateValue) },
};

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L107-L131
 */
/* NOTE: The SECG specification allows the private key structure
 * to contain curve parameters but recommends that they be stored
 * in the PrivateKeyAlgorithmIdentifier field of the PrivateKeyInfo
 * instead.
 */
const SEC_ASN1Template nsslowkey_ECPrivateKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(NSSLOWKEYPrivateKey) },
    { SEC_ASN1_INTEGER, offsetof(NSSLOWKEYPrivateKey, u.ec.version) },
    { SEC_ASN1_OCTET_STRING,
      offsetof(NSSLOWKEYPrivateKey, u.ec.privateValue) },
    /* We only support named curves for which the parameters are
     * encoded as an object ID.
     */
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED |
          SEC_ASN1_EXPLICIT | SEC_ASN1_CONTEXT_SPECIFIC |
          SEC_ASN1_XTRN | 0,
      offsetof(NSSLOWKEYPrivateKey, u.ec.ecParams.curveOID),
      SEC_ASN1_SUB(SEC_ObjectIDTemplate) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED |
          SEC_ASN1_EXPLICIT | SEC_ASN1_CONTEXT_SPECIFIC |
          SEC_ASN1_XTRN | 1,
      offsetof(NSSLOWKEYPrivateKey, u.ec.publicValue),
      SEC_ASN1_SUB(SEC_BitStringTemplate) },
    { 0 }
};

#pragma GCC diagnostic pop

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L141-L152
 */
void
prepare_low_rsa_priv_key_for_asn1(NSSLOWKEYPrivateKey *key)
{
    key->u.rsa.modulus.type = siUnsignedInteger;
    key->u.rsa.publicExponent.type = siUnsignedInteger;
    key->u.rsa.privateExponent.type = siUnsignedInteger;
    key->u.rsa.prime1.type = siUnsignedInteger;
    key->u.rsa.prime2.type = siUnsignedInteger;
    key->u.rsa.exponent1.type = siUnsignedInteger;
    key->u.rsa.exponent2.type = siUnsignedInteger;
    key->u.rsa.coefficient.type = siUnsignedInteger;
}

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L161-L167
 */
void
prepare_low_pqg_params_for_asn1(PQGParams *params)
{
    params->prime.type = siUnsignedInteger;
    params->subPrime.type = siUnsignedInteger;
    params->base.type = siUnsignedInteger;
}

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L179-L183
 */
void
prepare_low_dsa_priv_key_export_for_asn1(NSSLOWKEYPrivateKey *key)
{
    key->u.dsa.privateValue.type = siUnsignedInteger;
}

/*
https://github.com/nss-dev/nss/blob/NSS_3_97_RTM/lib/softoken/lowkey.c#L201-L209
 */
void
prepare_low_ec_priv_key_for_asn1(NSSLOWKEYPrivateKey *key)
{
    key->u.ec.version.type = siUnsignedInteger;
    key->u.ec.ecParams.DEREncoding.type = siUnsignedInteger;
    key->u.ec.ecParams.curveOID.type = siUnsignedInteger;
    key->u.ec.privateValue.type = siUnsignedInteger;
    key->u.ec.publicValue.type = siUnsignedInteger;
}
