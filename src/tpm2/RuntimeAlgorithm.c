/********************************************************************************/
/*										*/
/*			 Algorithm Runtime Disablement 				*/
/*			     Written by stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2022					*/
/*										*/
/********************************************************************************/

#define _GNU_SOURCE
#include <assert.h>
#include <string.h>

#include "RuntimeAlgorithm_fp.h"
#include "NVMarshal.h"
#include "GpMacros.h"

struct key_sizes {
    BOOL enabled;
    UINT16 size;
};

static const struct key_sizes key_sizes_aes[] = {
    { .enabled = AES_128, .size = 128 },
    { .enabled = AES_192, .size = 192 },
    { .enabled = AES_256, .size = 256 },
    { .enabled = false  , .size = 0 },
};
static const struct key_sizes key_sizes_sm4[] = {
    { .enabled = SM4_128, .size = 128 },
    { .enabled = false  , .size = 0 },
};
static const struct key_sizes key_sizes_camellia[] = {
    { .enabled = CAMELLIA_128, .size = 128 },
    { .enabled = CAMELLIA_192, .size = 192 },
    { .enabled = CAMELLIA_256, .size = 256 },
    { .enabled = false       , .size = 0 },
};
static const struct key_sizes key_sizes_tdes[] = {
    { .enabled = TDES_128, .size = 128 },
    { .enabled = TDES_192, .size = 192 },
    { .enabled = false   , .size = 0 },
};
static const struct key_sizes key_sizes_rsa[] = {
    { .enabled = RSA_1024, .size = 1024 },
    { .enabled = RSA_2048, .size = 2048 },
    { .enabled = RSA_3072, .size = 3072 },
    { .enabled = RSA_4096, .size = 4096 },
    { .enabled = false   , .size = 0 },
};
static const struct key_sizes key_sizes_ecc[] = {
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

static const struct algname_to_id {
    const char   *name;
    union {
	const struct key_sizes *keySizes;
    } u;
    BOOL          canBeDisabled;
} algname_to_id[] = {
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

    [TPM_ALG_RSA] = ASYMMETRIC(ALG_RSA, "rsa", key_sizes_rsa, false),
    [TPM_ALG_TDES] = SYMMETRIC(ALG_TDES, "tdes", key_sizes_tdes, true),
    [TPM_ALG_SHA1] = HASH(ALG_SHA1, "sha1", false),
    [TPM_ALG_HMAC] = SIGNING(ALG_HMAC, "hmac", false),
    [TPM_ALG_AES] = SYMMETRIC(ALG_AES, "aes", key_sizes_aes, false), // never disable: context encryption
    [TPM_ALG_MGF1] = HASH(ALG_MGF1, "mgf1", false),
    [TPM_ALG_KEYEDHASH] = HASH(ALG_KEYEDHASH, "keyedhash", false),
    [TPM_ALG_XOR] = OTHER(ALG_XOR, "xor", false),
    [TPM_ALG_SHA256] = HASH(ALG_SHA256, "sha256", false),
    [TPM_ALG_SHA384] = HASH(ALG_SHA384, "sha384", false),
    [TPM_ALG_SHA512] = HASH(ALG_SHA512, "sha512", false),
    [TPM_ALG_NULL] = OTHER(true, "null", false),
    [TPM_ALG_SM4] = SYMMETRIC(ALG_SM4, "sm4", key_sizes_sm4, false),
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
    [TPM_ALG_ECC] = ASYMMETRIC(ALG_ECC, "ecc", key_sizes_ecc, false),
    [TPM_ALG_SYMCIPHER] = OTHER(ALG_SYMCIPHER, "symcipher", false),
    [TPM_ALG_CAMELLIA] = SYMMETRIC(ALG_CAMELLIA, "camellia", key_sizes_camellia, true),
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

/* array holding minimum key sizes for algorithms in algsWithKeySizes */
static UINT16 s_algosMinimumKeySizes[ARRAY_SIZE(algname_to_id)];

static ALGORITHM_VECTOR s_enabledAlgorithms;

static char *s_profile;

static
unsigned int
KeySizesGetMinimum(const struct key_sizes *ks)
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
				    void
				    )
{
    TPM_ALG_ID algId;

    MemorySet(s_enabledAlgorithms, 0 , sizeof(s_enabledAlgorithms));

    for (algId = 0; algId < ARRAY_SIZE(algname_to_id); algId++) {
	// skip over unsupported algorithms
	if (!algname_to_id[algId].name)
	    continue;
	SET_BIT(algId, s_enabledAlgorithms);
    }
}

LIB_EXPORT void
RuntimeAlgorithmInit(void)
{
    TPM_ALG_ID algId;
    size_t i;

    MemorySet(s_algosMinimumKeySizes, 0 , sizeof(s_algosMinimumKeySizes));

    for (i = 0; i < ARRAY_SIZE(algsWithKeySizes); i++) {
	algId = algsWithKeySizes[i];
	assert(algId < ARRAY_SIZE(s_algosMinimumKeySizes));
	assert(algname_to_id[algId].u.keySizes != NULL);
	s_algosMinimumKeySizes[algId] = KeySizesGetMinimum(algname_to_id[algId].u.keySizes);
    }
}

/* Set the default profile with all algorithms and all keysizes enabled */
static void
RuntimeAlgorithmSetDefault(void)
{
    free(s_profile);
    s_profile = NULL;
    RuntimeAlgorithmInit();
    RuntimeAlgorithmEnableAllAlgorithms();
}

/* Set the given profile and runtime-enable the given algorihms. A NULL pointer
 * for the profile parameter sets the default profile which enables all algorithm
 * and all key sizes without any restrictions.
 */
LIB_EXPORT
TPM_RC
RuntimeAlgorithmSetProfile(
			   const char		*newProfile  // IN: comma-separated list of algorithm names
			   )
{
    unsigned long minKeySize;
    const char *token, *comma;
    size_t toklen, cmplen;
    TPM_ALG_ID algId;
    char *endptr;
    TPM_RC retVal = TPM_RC_SUCCESS;

    /* NULL pointer for profile enables all */
    if (!newProfile) {
	RuntimeAlgorithmSetDefault();
	return TPM_RC_SUCCESS;
    }

    MemorySet(s_enabledAlgorithms, 0, sizeof(s_enabledAlgorithms));

    token = newProfile;
    while (1) {
	comma = strchr(token, ',');
	if (comma)
	    toklen = (size_t)(comma - token);
	else
	    toklen = strlen(token);

	for (algId = 0; algId < ARRAY_SIZE(algname_to_id); algId++) {
	    // skip over unsupported algorithms
	    if (!algname_to_id[algId].name)
		continue;
	    cmplen = MAX(strlen(algname_to_id[algId].name), toklen);
	    if (!strncmp(token, algname_to_id[algId].name, cmplen)) {
		SET_BIT(algId, s_enabledAlgorithms);
	    } else if (algname_to_id[algId].u.keySizes) {
		size_t algnamelen = strlen(algname_to_id[algId].name);
		if (strncmp(token, algname_to_id[algId].name, algnamelen) ||
		    strncmp(&token[algnamelen], "-min-size=", 10))
		    continue;
		minKeySize = strtoul(&token[algnamelen + 10], &endptr, 10);
		if ((*endptr != ',' && *endptr != '\0') ||  minKeySize > 4096) {
		    retVal = TPM_RC_KEY_SIZE;
		    goto exit;
		}
		s_algosMinimumKeySizes[algId] = (UINT16)minKeySize;
	    }
	}

	if (!comma)
	    break;
	token = &comma[1];
    }

    /* reconcile with what can be disabled per code instrumentation */
    for (algId = 0; algId < ARRAY_SIZE(algname_to_id); algId++) {
	// skip over unsupported algorithms
	if (!algname_to_id[algId].name)
	    continue;
	if (!algname_to_id[algId].canBeDisabled && !TEST_BIT(algId, s_enabledAlgorithms)) {
	    retVal = TPM_RC_FAILURE;
	    goto exit;
	}
    }

    /* some consistency checks */
    /* Do not allow aes-min-size > 128 while RSA=2048 otherwise standard EK certs cannot be created anymore */
    if (s_algosMinimumKeySizes[TPM_ALG_AES] > 128 &&
	s_algosMinimumKeySizes[TPM_ALG_RSA] == 2048) {
	retVal = TPM_RC_KEY_SIZE;
	goto exit;
    }

    s_profile = strdup(newProfile);
    if (!s_profile)
	retVal = TPM_RC_MEMORY;

exit:
    if (retVal != TPM_RC_SUCCESS)
	RuntimeAlgorithmSetDefault();

    return retVal;
}

LIB_EXPORT
const char *
RuntimeAlgorithmGetProfile(
			   void
			   )
{
    return s_profile;
}

LIB_EXPORT
TPM_RC
RuntimeAlgorithmSwitchProfile(
			      const char *newProfile,
			      char **oldProfile
			      )
{
    TPM_RC retVal;

    *oldProfile = s_profile;
    s_profile = NULL;

    retVal = RuntimeAlgorithmSetProfile(newProfile);
    if (retVal != TPM_RC_SUCCESS) {
	RuntimeAlgorithmSetProfile(*oldProfile);
	*oldProfile = NULL;
    }
    return retVal;
}

/* Check whether the given algorithm is runtime-disabled */
LIB_EXPORT BOOL
RuntimeAlgorithmCheckEnabled(
			     TPM_ALG_ID	   algId      // IN: the algorithm to check
			     )
{
    if (!TEST_BIT(algId, s_enabledAlgorithms))
	return FALSE;
    return TRUE;
}

/* Check whether the given symmetric or asymmetric crypto algorithm is enabled
 * for the given keysize */
LIB_EXPORT BOOL
RuntimeAlgorithmKeySizeCheckEnabled(
				    TPM_ALG_ID   algId,	 // IN: the algorithm to check
				    UINT16       keySizeInBits  // IN: size of the key in bits
				    )
{
    UINT16 minKeySize;

    if (!RuntimeAlgorithmCheckEnabled(algId))
    	return FALSE;

    minKeySize = s_algosMinimumKeySizes[algId];
    if (minKeySize > keySizeInBits)
	return FALSE;

    return TRUE;
}

LIB_EXPORT
char *
RuntimeAlgorithmGet(
		    enum RuntimeAlgorithmType rat
		    )
{
    char *buffer, *nbuffer = NULL;
    unsigned int minKeySize;
    TPM_ALG_ID algId;
    int n;
    BOOL first = true;

    buffer = strdup("[");
    if (!buffer)
	return NULL;

    for (algId = 0; algId < ARRAY_SIZE(algname_to_id); algId++) {
	// skip over unsupported algorithms
	if (!algname_to_id[algId].name)
	    continue;
	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    // no filter
	    break;
	case RUNTIME_ALGO_CAN_BE_DISABLED:
	    if (!algname_to_id[algId].canBeDisabled)
		 continue;
	    break;
	case RUNTIME_ALGO_ENABLED:
	    // skip over disabled ones
	    if (!RuntimeAlgorithmCheckEnabled(algId))
		continue;
	    break;
	case RUNTIME_ALGO_DISABLED:
	    // skip over enabled ones
	    if (RuntimeAlgorithmCheckEnabled(algId))
		continue;
	    break;
	default:
	    continue;
	}
	n = asprintf(&nbuffer, "%s%s\"%s\"",
		     buffer ? buffer : "",
		     first ? "" : ",",
		     algname_to_id[algId].name);
	if (n < 0) {
	     free(buffer);
	     return NULL;
	}
	buffer = nbuffer;
	first = false;

	minKeySize = 0;

	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    if (algname_to_id[algId].u.keySizes) {
		minKeySize = KeySizesGetMinimum(algname_to_id[algId].u.keySizes);
	    }
	    break;
	case RUNTIME_ALGO_ENABLED:
	    if (algname_to_id[algId].u.keySizes) {
		minKeySize = s_algosMinimumKeySizes[algId];
	    }
	    break;
	default:
	}
	if (minKeySize > 0) {
	    n = asprintf(&nbuffer, "%s,\"%s-min-size=%u\"",
			 buffer,
			 algname_to_id[algId].name,
			 minKeySize);
	    if (n < 0) {
		free(buffer);
		return NULL;
	    }
	    buffer = nbuffer;
	}
    }

    n = asprintf(&nbuffer, "%s]", buffer);
    free(buffer);

    return nbuffer;
}
