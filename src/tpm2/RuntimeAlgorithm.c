/********************************************************************************/
/*										*/
/*			 Algorithm Runtime Disablement 				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  (c) Copyright IBM Corporation, 2022						*/
/*										*/
/* All rights reserved.								*/
/*										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/*										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/*										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/*										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/*										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/*										*/
/********************************************************************************/

#define _GNU_SOURCE
#include <assert.h>
#include <string.h>

#include "Tpm.h"
#include "NVMarshal.h"
#include "GpMacros.h"
#include "tpm_library_intern.h"

#define ALGO_SEPARATOR_C ','
#define ALGO_SEPARATOR_STR ","

struct KeySizes {
    BOOL enabled;
    UINT16 size;
};

static const struct KeySizes s_KeySizesAES[] = {
    { .enabled = AES_128, .size = 128 },
    { .enabled = AES_192, .size = 192 },
    { .enabled = AES_256, .size = 256 },
    { .enabled = false  , .size = 0 },
};
static const struct KeySizes s_KeySizesSM4[] = {
    { .enabled = SM4_128, .size = 128 },
    { .enabled = false  , .size = 0 },
};
static const struct KeySizes s_KeySizesCamellia[] = {
    { .enabled = CAMELLIA_128, .size = 128 },
    { .enabled = CAMELLIA_192, .size = 192 },
    { .enabled = CAMELLIA_256, .size = 256 },
    { .enabled = false       , .size = 0 },
};
static const struct KeySizes s_KeySizesTDES[] = {
    { .enabled = TDES_128, .size = 128 },
    { .enabled = TDES_192, .size = 192 },
    { .enabled = false   , .size = 0 },
};
static const struct KeySizes s_KeySizesRSA[] = {
    { .enabled = RSA_1024, .size = 1024 },
    { .enabled = RSA_2048, .size = 2048 },
    { .enabled = RSA_3072, .size = 3072 },
    { .enabled = RSA_4096, .size = 4096 },
    { .enabled = false   , .size = 0 },
};
static const struct KeySizes s_KeySizesECC[] = {
    { .enabled = ECC_NIST_P192, .size = 192 },
    { .enabled = ECC_NIST_P224, .size = 224 },
    { .enabled = ECC_NIST_P256, .size = 256 },
    { .enabled = ECC_BN_P256  , .size = 256 },
    { .enabled = ECC_SM2_P256 , .size = 256 },
    { .enabled = ECC_NIST_P384, .size = 384 },
    { .enabled = ECC_NIST_P521, .size = 521 },
    { .enabled = ECC_BN_P638  , .size = 638 },
    { .enabled = false        , .size = 0 },
};

static const struct {
    const char   *name;
    union {
	const struct KeySizes *keySizes;
    } u;
    BOOL          canBeDisabled;
} s_AlgorithmProperties[NUM_ENTRIES_ALGORITHM_PROPERTIES] = {
#define SYMMETRIC(ENABLED, NAME, KEYSIZES, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .u.keySizes = KEYSIZES, .canBeDisabled = CANDISABLE }
#define ASYMMETRIC(ENABLED, NAME, KEYSIZES, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .u.keySizes = KEYSIZES, .canBeDisabled = CANDISABLE }
#define HASH(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }
#define SIGNING(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }
#define ENCRYPTING(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }
#define OTHER(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }

    [TPM_ALG_RSA] = ASYMMETRIC(ALG_RSA, "rsa", s_KeySizesRSA, false),
    [TPM_ALG_TDES] = SYMMETRIC(ALG_TDES, "tdes", s_KeySizesTDES, false),
    [TPM_ALG_SHA1] = HASH(ALG_SHA1, "sha1", false),
    [TPM_ALG_HMAC] = SIGNING(ALG_HMAC, "hmac", false),
    [TPM_ALG_AES] = SYMMETRIC(ALG_AES, "aes", s_KeySizesAES, false), // never disable: context encryption
    [TPM_ALG_MGF1] = HASH(ALG_MGF1, "mgf1", false),
    [TPM_ALG_KEYEDHASH] = HASH(ALG_KEYEDHASH, "keyedhash", false),
    [TPM_ALG_XOR] = OTHER(ALG_XOR, "xor", false),
    [TPM_ALG_SHA256] = HASH(ALG_SHA256, "sha256", false),
    [TPM_ALG_SHA384] = HASH(ALG_SHA384, "sha384", false),
    [TPM_ALG_SHA512] = HASH(ALG_SHA512, "sha512", false),
    [TPM_ALG_NULL] = OTHER(true, "null", false),
    [TPM_ALG_SM4] = SYMMETRIC(ALG_SM4, "sm4", s_KeySizesSM4, false),
    [TPM_ALG_RSASSA] = SIGNING(ALG_RSASSA, "rsassa", false),
    [TPM_ALG_RSAES] = ENCRYPTING(ALG_RSAES, "rsaes", false),
    [TPM_ALG_RSAPSS] = SIGNING(ALG_RSAPSS, "rsapss", false),
    [TPM_ALG_OAEP] = ENCRYPTING(ALG_OAEP, "oaep", false), // never disable: CryptSecretEncrypt/Decrypt needs it
    [TPM_ALG_ECDSA] = SIGNING(ALG_ECDSA, "ecdsa", false),
    [TPM_ALG_ECDH] = OTHER(ALG_ECDH, "ecdh", false),
    [TPM_ALG_ECDAA] = OTHER(ALG_ECDAA, "ecdaa", false),
    [TPM_ALG_SM2] = SIGNING(ALG_SM2, "sm2", false),
    [TPM_ALG_ECSCHNORR] = SIGNING(ALG_ECSCHNORR, "ecschnorr", false),
    [TPM_ALG_ECMQV] = OTHER(ALG_ECMQV, "ecmqv", false),
    [TPM_ALG_KDF1_SP800_56A] = HASH(ALG_KDF1_SP800_56A, "kdf1-sp800-56a", false),
    [TPM_ALG_KDF2] = HASH(ALG_KDF2, "kdf2", false),
    [TPM_ALG_KDF1_SP800_108] = HASH(ALG_KDF1_SP800_108, "kdf1-sp800-108", false),
    [TPM_ALG_ECC] = ASYMMETRIC(ALG_ECC, "ecc", s_KeySizesECC, false),
    [TPM_ALG_SYMCIPHER] = OTHER(ALG_SYMCIPHER, "symcipher", false),
    [TPM_ALG_CAMELLIA] = SYMMETRIC(ALG_CAMELLIA, "camellia", s_KeySizesCamellia, true),
    [TPM_ALG_SHA3_256] = HASH(ALG_SHA3_256, "sha3-256", false),
    [TPM_ALG_SHA3_384] = HASH(ALG_SHA3_384, "sha3-384", false),
    [TPM_ALG_SHA3_512] = HASH(ALG_SHA3_512, "sha3-256", false),
    [TPM_ALG_CMAC] = SIGNING(ALG_CMAC, "cmac", false),
    [TPM_ALG_CTR] = ENCRYPTING(ALG_CTR, "ctr", false),
    [TPM_ALG_OFB] = ENCRYPTING(ALG_OFB, "ofb", false),
    [TPM_ALG_CBC] = ENCRYPTING(ALG_CBC, "cbc", false),
    [TPM_ALG_CFB] = ENCRYPTING(ALG_CFB, "cfb", false), // never disable: context entryption
    [TPM_ALG_ECB] = ENCRYPTING(ALG_ECB, "ecb", false),
};

static const TPM_ALG_ID algsWithKeySizes[] = {
    TPM_ALG_RSA,
    TPM_ALG_TDES,
    TPM_ALG_AES,
    TPM_ALG_SM4,
    TPM_ALG_CAMELLIA,
};

static unsigned int
KeySizesGetMinimum(const struct KeySizes *ks)
{
    size_t i = 0;

    while (ks[i].size) {
	if (ks[i].enabled)
	    return ks[i].size;
	i++;
    }
    return 0;
}

static void
RuntimeAlgorithmEnableAllAlgorithms(
				    struct RuntimeAlgorithm *RuntimeAlgorithm
				    )
{
    TPM_ALG_ID algId;

    MemorySet(RuntimeAlgorithm->enabledAlgorithms, 0 , sizeof(RuntimeAlgorithm->enabledAlgorithms));

    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	/* skip over unsupported algorithms */
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	SET_BIT(algId, RuntimeAlgorithm->enabledAlgorithms);
    }
}

LIB_EXPORT void
RuntimeAlgorithmInit(
		     struct RuntimeAlgorithm *RuntimeAlgorithm
		     )
{
    TPM_ALG_ID algId;
    size_t i;

    MemorySet(RuntimeAlgorithm->algosMinimumKeySizes, 0 , sizeof(RuntimeAlgorithm->algosMinimumKeySizes));

    for (i = 0; i < ARRAY_SIZE(algsWithKeySizes); i++) {
	algId = algsWithKeySizes[i];
	assert(algId < ARRAY_SIZE(RuntimeAlgorithm->algosMinimumKeySizes));
	assert(s_AlgorithmProperties[algId].u.keySizes != NULL);
	RuntimeAlgorithm->algosMinimumKeySizes[algId] = KeySizesGetMinimum(s_AlgorithmProperties[algId].u.keySizes);
    }
}

LIB_EXPORT void
RuntimeAlgorithmFree(
		     struct RuntimeAlgorithm *RuntimeAlgorithm
		     )
{
    free(RuntimeAlgorithm->algorithmProfile);
    RuntimeAlgorithm->algorithmProfile = NULL;
}

/* Set the default profile with all algorithms and all keysizes enabled */
static void
RuntimeAlgorithmSetDefault(
			   struct RuntimeAlgorithm *RuntimeAlgorithm
			   )
{
    free(RuntimeAlgorithm->algorithmProfile);
    RuntimeAlgorithm->algorithmProfile = NULL;
    RuntimeAlgorithmInit(RuntimeAlgorithm);
    RuntimeAlgorithmEnableAllAlgorithms(RuntimeAlgorithm);
}

/* Set the given profile and runtime-enable the given algorithms. A NULL pointer
 * for the profile parameter sets the default profile which enables all algorithms
 * and all key sizes without any restrictions.
 */
LIB_EXPORT TPM_RC
RuntimeAlgorithmSetProfile(
			   struct RuntimeAlgorithm  *RuntimeAlgorithm,
			   const char		    *newProfile  // IN: colon-separated list of algorithm names
			   )
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    unsigned long minKeySize;
    const char *token, *comma;
    size_t toklen, cmplen;
    TPM_ALG_ID algId;
    char *endptr;
    bool found;

    /* NULL pointer for profile enables all */
    if (!newProfile) {
	RuntimeAlgorithmSetDefault(RuntimeAlgorithm);
	return TPM_RC_SUCCESS;
    }

    MemorySet(RuntimeAlgorithm->enabledAlgorithms, 0, sizeof(RuntimeAlgorithm->enabledAlgorithms));

    token = newProfile;
    while (1) {
	comma = strchr(token, ALGO_SEPARATOR_C);
	if (comma)
	    toklen = (size_t)(comma - token);
	else
	    toklen = strlen(token);

	found = false;
	for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	    /* skip over unsupported algorithms */
	    if (!s_AlgorithmProperties[algId].name)
		continue;
	    cmplen = MAX(strlen(s_AlgorithmProperties[algId].name), toklen);
	    if (!strncmp(token, s_AlgorithmProperties[algId].name, cmplen)) {
		SET_BIT(algId, RuntimeAlgorithm->enabledAlgorithms);
		found = true;
		break;
	    } else if (s_AlgorithmProperties[algId].u.keySizes) {
		size_t algnamelen = strlen(s_AlgorithmProperties[algId].name);
		if (strncmp(token, s_AlgorithmProperties[algId].name, algnamelen) ||
		    strncmp(&token[algnamelen], "-min-size=", 10))
		    continue;
		minKeySize = strtoul(&token[algnamelen + 10], &endptr, 10);
		if ((*endptr != ALGO_SEPARATOR_C && *endptr != '\0') ||  minKeySize > 4096) {
		    retVal = TPM_RC_KEY_SIZE;
		    goto exit;
		}
		RuntimeAlgorithm->algosMinimumKeySizes[algId] = (UINT16)minKeySize;
		found = true;
		break;
	    }
	}
	if (!found) {
	    TPMLIB_LogTPM2Error("Requested algorithm specifier %.*s is not supported.\n",
				(int)toklen, token);
	    retVal = TPM_RC_FAILURE;
	    goto exit;
	}

	if (!comma)
	    break;
	token = &comma[1];
    }

    /* reconcile with what can be disabled per code instrumentation */
    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	/* skip over unsupported algorithms */
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	if (!s_AlgorithmProperties[algId].canBeDisabled && !TEST_BIT(algId, RuntimeAlgorithm->enabledAlgorithms)) {
	    retVal = TPM_RC_FAILURE;
	    goto exit;
	}
    }

    /* some consistency checks */
    /* Do not allow aes-min-size > 128 while RSA=2048 otherwise standard EK certs cannot be created anymore */
    if (RuntimeAlgorithm->algosMinimumKeySizes[TPM_ALG_AES] > 128 &&
	RuntimeAlgorithm->algosMinimumKeySizes[TPM_ALG_RSA] == 2048) {
	retVal = TPM_RC_KEY_SIZE;
	goto exit;
    }

    RuntimeAlgorithm->algorithmProfile = strdup(newProfile);
    if (!RuntimeAlgorithm->algorithmProfile)
	retVal = TPM_RC_MEMORY;

exit:
    if (retVal != TPM_RC_SUCCESS)
	RuntimeAlgorithmSetDefault(RuntimeAlgorithm);

    return retVal;
}

LIB_EXPORT TPM_RC
RuntimeAlgorithmSwitchProfile(
			      struct RuntimeAlgorithm  *RuntimeAlgorithm,
			      const char               *newProfile,
			      char                    **oldProfile
			      )
{
    TPM_RC retVal;

    *oldProfile = RuntimeAlgorithm->algorithmProfile;
    RuntimeAlgorithm->algorithmProfile = NULL;

    retVal = RuntimeAlgorithmSetProfile(RuntimeAlgorithm, newProfile);
    if (retVal != TPM_RC_SUCCESS) {
	RuntimeAlgorithmSetProfile(RuntimeAlgorithm, *oldProfile);
	*oldProfile = NULL;
    }
    return retVal;
}

/* Check whether the given algorithm is runtime-disabled */
LIB_EXPORT BOOL
RuntimeAlgorithmCheckEnabled(
			     struct RuntimeAlgorithm *RuntimeAlgorithm,
			     TPM_ALG_ID	              algId      // IN: the algorithm to check
			     )
{
    if (!TEST_BIT(algId, RuntimeAlgorithm->enabledAlgorithms))
	return FALSE;
    return TRUE;
}

/* Check whether the given symmetric or asymmetric crypto algorithm is enabled
 * for the given keysize */
LIB_EXPORT BOOL
RuntimeAlgorithmKeySizeCheckEnabled(
				    struct RuntimeAlgorithm *RuntimeAlgorithm,
				    TPM_ALG_ID               algId,		// IN: the algorithm to check
				    UINT16                   keySizeInBits	// IN: size of the key in bits
				    )
{
    UINT16 minKeySize;

    if (!RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
	return FALSE;

    minKeySize = RuntimeAlgorithm->algosMinimumKeySizes[algId];
    if (minKeySize > keySizeInBits)
	return FALSE;

    return TRUE;
}

LIB_EXPORT char *
RuntimeAlgorithmGet(
		    struct RuntimeAlgorithm   *RuntimeAlgorithm,
		    enum RuntimeAlgorithmType rat
		    )
{
    char *buffer, *nbuffer = NULL;
    unsigned int minKeySize;
    TPM_ALG_ID algId;
    int n;
    BOOL first = true;

    buffer = strdup("\"");
    if (!buffer)
	return NULL;

    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	// skip over unsupported algorithms
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    // no filter
	    break;
	case RUNTIME_ALGO_CAN_BE_DISABLED:
	    if (!s_AlgorithmProperties[algId].canBeDisabled)
		 continue;
	    break;
	case RUNTIME_ALGO_ENABLED:
	    // skip over disabled ones
	    if (!RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
		continue;
	    break;
	case RUNTIME_ALGO_DISABLED:
	    // skip over enabled ones
	    if (RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
		continue;
	    break;
	default:
	    continue;
	}
	n = asprintf(&nbuffer, "%s%s%s",
		     buffer ? buffer : "",
		     first ? "" : ALGO_SEPARATOR_STR,
		     s_AlgorithmProperties[algId].name);
	free(buffer);
	if (n < 0)
	     return NULL;

	buffer = nbuffer;
	first = false;

	minKeySize = 0;

	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    if (s_AlgorithmProperties[algId].u.keySizes) {
		minKeySize = KeySizesGetMinimum(s_AlgorithmProperties[algId].u.keySizes);
	    }
	    break;
	case RUNTIME_ALGO_ENABLED:
	    if (s_AlgorithmProperties[algId].u.keySizes) {
		minKeySize = RuntimeAlgorithm->algosMinimumKeySizes[algId];
	    }
	    break;
	default:
	    break;
	}
	if (minKeySize > 0) {
	    n = asprintf(&nbuffer, "%s%s%s-min-size=%u",
			 buffer,
			 ALGO_SEPARATOR_STR,
			 s_AlgorithmProperties[algId].name,
			 minKeySize);
	    free(buffer);
	    if (n < 0)
		return NULL;

	    buffer = nbuffer;
	}
    }

    n = asprintf(&nbuffer, "%s\"", buffer);
    free(buffer);

    return nbuffer;
}
