/********************************************************************************/
/*										*/
/*			       Runtime Profile 					*/
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
#include <errno.h>
#include <stdio.h>
#include <regex.h>

#include "Tpm.h"
#include "tpm_library_intern.h"

struct RuntimeProfile g_RuntimeProfile;

static const struct RuntimeProfileDesc {
    const char *name;
    const char *commandsProfile;
    const char *algorithmsProfile;
    /* StateFormatLevel drives the format the TPM's state is written in and
     * how it is read.
     * Once a version of libtpms is released this field must never change afterwards
     * so that backwards compatibility for reading the state can be maintained.
     * This basically locks the name of the profile to the stateFormatLevel.
     */
    unsigned int stateFormatLevel;
#define STATE_FORMAT_LEVEL_CURRENT 1
#define STATE_FORMAT_LEVEL_UNKNOWN 0 /* JSON didn't provide StateFormatLevel; this is only
                                        allowed for the 'default' profile or when user
                                        passed JSON via SetProfile() */
} RuntimeProfileDescs[] = {
    {
        /* When the user gives no profile, then the 'default' profile is applied which locks the
         * TPM 2 into a set of commands and algorithms that are enabled.
         */
	.name = "default",
	.commandsProfile   = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"
			     "0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
	.algorithmsProfile = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,"
			     "aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,"
			     "null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
			     "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,symcipher,"
			     "camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb",
	.stateFormatLevel  = 1,
    }, {
        /* When state has no profile, then the 'null' profile is applied which locks the
         * TPM 2 into a set of commands and algorithms that were enable for libtpms v0.9
         */
	.name = "null",
	.commandsProfile   = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"
			     "0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
	.algorithmsProfile = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,"
			     "aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,"
			     "null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
			     "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,symcipher,"
			     "camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb",
	.stateFormatLevel  = 1, /* NEVER change */
    }, {
	.name = "fips-2022",
	.commandsProfile   = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"
	                     "0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
        /*
         * removed: rsa-1024, sha1, rsapss (not available CentOS FIPS mode),
         *          camellia (CentOS), tdes (CentOS)
         * Note: Test suites will fail!
         */
	.algorithmsProfile = "rsa,rsa-min-size=2048,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
	                     "xor,sha256,sha384,sha512,null,rsassa,rsaes,oaep,ecdsa,ecdh,ecdaa,"
	                     "sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,"
	                     "symcipher,cmac,ctr,ofb,cbc,cfb,ecb,ecc-min-size=256",
	.stateFormatLevel  = 1,
    }, {
        // FIXME: test profile
	.name = "1",
	.commandsProfile = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
	.stateFormatLevel = 1,
    }
};

/* Current state format level this version of libtpms implements.
 * This is to be bumped up every time new parts of the state need to be written.
 */
static const unsigned int s_currentStateFormatLevel = STATE_FORMAT_LEVEL_CURRENT;

LIB_EXPORT TPM_RC
RuntimeProfileInit(
		   struct RuntimeProfile *RuntimeProfile
		   )
{
    RuntimeAlgorithmInit(&RuntimeProfile->RuntimeAlgorithm);
    RuntimeCommandsInit(&RuntimeProfile->RuntimeCommands);

    RuntimeProfile->profileName = NULL;
    RuntimeProfile->runtimeProfileJSON = NULL;
    RuntimeProfile->stateFormatLevel = STATE_FORMAT_LEVEL_UNKNOWN;
    RuntimeProfile->wasNullProfile = FALSE;

    return TPM_RC_SUCCESS;
}

void
RuntimeProfileFree(
		   struct RuntimeProfile *RuntimeProfile
		   )
{
    RuntimeAlgorithmFree(&RuntimeProfile->RuntimeAlgorithm);
    RuntimeCommandsFree(&RuntimeProfile->RuntimeCommands);

    free(RuntimeProfile->profileName);
    RuntimeProfile->profileName = NULL;

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = NULL;
}

static TPM_RC
RuntimeProfileSetRuntimeProfile(
				struct RuntimeProfile           *RuntimeProfile,
				const struct RuntimeProfileDesc *rp,
				const char                      *algorithmsProfile,
				const char                      *commandsProfile
				)
{
    TPM_RC retVal;

    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm, algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    return RuntimeCommandsSetProfile(&RuntimeProfile->RuntimeCommands, commandsProfile);
}

static TPM_RC
RuntimeProfileCheckJSON(const char *json)
{
#define MAP_ENTRY_REGEX "[[:space:]]*\"[^\"]+\"[[:space:]]*:[[:space:]]*(\"[^\"]+\"|[[:digit:]]+)[[:space:]]*"
    const char *regex = "^\\{[[:space:]]*("MAP_ENTRY_REGEX")?(,"MAP_ENTRY_REGEX")*\\}$";
#undef MAP_ENTRY_REGEX
    TPM_RC retVal;
    regex_t r;

    if (regcomp(&r, regex, REG_EXTENDED|REG_NOSUB) != 0)
	return TPM_RC_FAILURE;

    if (regexec(&r, json, 0, NULL, 0) == REG_NOMATCH) {
	retVal = TPM_RC_NO_RESULT;
	goto exit;
    }
    retVal = TPM_RC_SUCCESS;

exit:
    regfree(&r);
    return retVal;
}

static TPM_RC
RuntimeProfileGetFromJSON(
			  const char  *json,
			  const char  *regex,
			  char       **value
			  )
{
    regmatch_t match[2];
    TPM_RC retVal;
    regex_t r;

    if (regcomp(&r, regex, REG_EXTENDED) != 0)
	return TPM_RC_FAILURE;

    if (regexec(&r, json, 2, match, 0) == REG_NOMATCH) {
	retVal = TPM_RC_NO_RESULT;
	goto exit;
    }

    if (match[1].rm_eo - match[1].rm_so == 0) {
	retVal = TPM_RC_SIZE;
	goto exit;
    }

    *value = strndup(&json[match[1].rm_so], match[1].rm_eo - match[1].rm_so);
    if (*value == NULL) {
	retVal= TPM_RC_MEMORY;
	goto exit;
    }
    retVal = TPM_RC_SUCCESS;

exit:
    regfree(&r);

    return retVal;
}

static TPM_RC
RuntimeProfileGetNameFromJSON(
			      const char  *json,
			      char       **name
			      )
{
    const char *regex = "^\\{.*[[:space:]]*\"name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";

    return RuntimeProfileGetFromJSON(json, regex, name);
}

static TPM_RC
GetStateFormatLevelFromJSON(
			    const char    *json,
			    unsigned int  *stateFormatLevel
			    )
{
    const char *regex = "^\\{.*[[:space:]]*\"stateFormatLevel\"[[:space:]]*:[[:space:]]*([0-9]+).*\\}$";
    char *str = NULL;
    unsigned long v;
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, &str);
    if (retVal == TPM_RC_NO_RESULT) {
	*stateFormatLevel = STATE_FORMAT_LEVEL_UNKNOWN;
	return TPM_RC_SUCCESS;
    }
    if (retVal)
	return retVal;

    errno = 0;
    v = strtoul(str, NULL, 10);
    if (v > UINT_MAX || errno)
	retVal = TPM_RC_FAILURE;
    else
	*stateFormatLevel = v;

    free(str);

    return retVal;
}

static TPM_RC
GetAlgorithmsProfileFromJSON(
			     const char  *json,
			     char       **algorithmsProfile
			     )
{
    const char *regex = "^\\{.*[[:space:]]*\"algorithms\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, algorithmsProfile);
    if (retVal == TPM_RC_NO_RESULT) {
	*algorithmsProfile = NULL;
	retVal = 0;
    }
    return retVal;
}

static TPM_RC
GetCommandsProfileFromJSON(
			   const char  *json,
			   char       **commandsProfile
			   )
{
    const char *regex = "^\\{.*[[:space:]]*\"commands\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, commandsProfile);
    if (retVal == TPM_RC_NO_RESULT) {
	*commandsProfile = NULL;
	retVal = 0;
    }
    return retVal;
}

static TPM_RC
GetParametersFromJSON(
		      const char    *jsonProfile,
		      bool           jsonProfileIsFromUser,
		      char         **profileName,
		      unsigned int  *stateFormatLevel,
		      char         **algorithmsProfile,
		      char         **commandsProfile
		      )
{
    TPM_RC retVal;

    if (!jsonProfile) {
        if (jsonProfileIsFromUser)
	    *profileName = strdup("default");
	else
	    *profileName = strdup("null");
	if (*profileName == NULL)
	    return TPM_RC_MEMORY;

        *stateFormatLevel = STATE_FORMAT_LEVEL_CURRENT;
	return TPM_RC_SUCCESS;
    }

    retVal = RuntimeProfileCheckJSON(jsonProfile);
    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    retVal = RuntimeProfileGetNameFromJSON(jsonProfile, profileName);
    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    retVal = GetStateFormatLevelFromJSON(jsonProfile, stateFormatLevel);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_profilename;

    retVal = GetAlgorithmsProfileFromJSON(jsonProfile, algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_profilename;

    retVal = GetCommandsProfileFromJSON(jsonProfile, commandsProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_algorithmsprofile;

    return TPM_RC_SUCCESS;

err_free_algorithmsprofile:
    free(*algorithmsProfile);

err_free_profilename:
    free(*profileName);

    return retVal;
}

static TPM_RC
RuntimeProfileFormat(
                     char          **json,
                     const char     *profileName,
                     unsigned int    stateFormatLevel,
                     const char     *algorithmsProfile,
                     const char     *commandsProfile
                     )
{
    char *ret, *nret;
    int n;

    if (!profileName)
	return TPM_RC_FAILURE;

    n = asprintf(&ret,
                 "{\"name\":\"%s\","
                  "\"stateFormatLevel\":%d",
                  profileName, stateFormatLevel);
    if (n < 0)
	return TPM_RC_MEMORY;
    if (commandsProfile) {
	n = asprintf(&nret, "%s,\"commands\":\"%s\"", ret, commandsProfile);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    if (algorithmsProfile) {
	n = asprintf(&nret, "%s,\"algorithms\":\"%s\"", ret, algorithmsProfile);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    n = asprintf(&nret, "%s}", ret);
    free(ret);
    if (n < 0)
       return TPM_RC_MEMORY;

    *json = nret;

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
RuntimeProfileFormatJSON(
			 struct RuntimeProfile *RuntimeProfile
			 )
{
    char *runtimeProfileJSON = NULL;
    TPM_RC retVal;

    if (!RuntimeProfile->profileName)
	return TPM_RC_FAILURE;

    retVal = RuntimeProfileFormat(&runtimeProfileJSON,
				  RuntimeProfile->profileName,
				  RuntimeProfile->stateFormatLevel,
				  RuntimeProfile->RuntimeAlgorithm.algorithmProfile,
				  RuntimeProfile->RuntimeCommands.commandsProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = runtimeProfileJSON;

    return TPM_RC_SUCCESS;
}

static TPM_RC
CheckStateFormatLevel(
		      const struct RuntimeProfileDesc *rpd,
		      unsigned int                    *stateFormatLevel,
		      bool                             jsonFromUser
		      )
{
    TPM_RC retVal = TPM_RC_SUCCESS;

    /* the stateFormatLevel must never be larger than the one implemented */
    if (*stateFormatLevel > s_currentStateFormatLevel) {
	if (!jsonFromUser)
	    TPMLIB_LogPrintf("StateFormatLevel beyond supported level: %d > %d\n",
	                     *stateFormatLevel, s_currentStateFormatLevel);
	return TPM_RC_FAILURE;
    }

    if (strcmp(rpd->name, "default") == 0) {
	if (jsonFromUser) {
	    /* If the default profile is chosen due to the user providing it
	     * choose the latest StateFormatLevel.
	     */
	    *stateFormatLevel = s_currentStateFormatLevel;
	} else {
	    /* If the default profile is chose due to not finding a profile
	     * in the TPM 2's state then set the StateFormatLevel to '1'.
	     */
	    *stateFormatLevel = 1;
	}
    } else if (strcmp(rpd->name, "null") == 0) {
	*stateFormatLevel = rpd->stateFormatLevel;
    } else {
	if (jsonFromUser) {
	    /* If user passed JSON and it didn't contain a stateFormatLevel take
	     * it from the profile description.
	     */
	    if (*stateFormatLevel == STATE_FORMAT_LEVEL_UNKNOWN)
		*stateFormatLevel = rpd->stateFormatLevel;
	} else {
	    /* stateFormatLevel from JSON from TPM 2 state file must have a good value */
	    if (*stateFormatLevel == STATE_FORMAT_LEVEL_UNKNOWN) {
		TPMLIB_LogPrintf("Missing StateFormatLevel\n");
		retVal = TPM_RC_FAILURE;
	    }
	}
    }
    return retVal;
}

/*
 * Set the given RuntimeProfile to the profile in JSON format. The profile may
 * be set by the user and in this case the jsonProfileIsFromUser is set to
 * true. Otherwise, it may originate from the TPM 2's state file and in this
 * case jsonProfileIsFromUser is false.
 * If jsonProfileIsFromUser is 'true' then the the default profile will get
 * the latest StateFormatLevel version number, otherwise it will get the
 * StateFormatLevel '1' if no stateFormatLevel field is found in the JSON
 * profile.
 */
LIB_EXPORT TPM_RC
RuntimeProfileSet(
		  struct RuntimeProfile *RuntimeProfile,
		  const char	        *jsonProfile,
		  bool                   jsonProfileIsFromUser
		  )
{
    const struct RuntimeProfileDesc *rp = NULL;
    char *runtimeProfileJSON = NULL;
    char *algorithmsProfile = NULL;
    char *commandsProfile = NULL;
    unsigned int stateFormatLevel;
    char *profileName = NULL;
    TPM_RC retVal;
    size_t i;

    retVal = GetParametersFromJSON(jsonProfile, jsonProfileIsFromUser,
				   &profileName, &stateFormatLevel,
				   &algorithmsProfile, &commandsProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    if (jsonProfileIsFromUser) {
        /* user cannot set commands profile */
        free(commandsProfile);
        commandsProfile = NULL;
    }

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    rp = &RuntimeProfileDescs[i];

	    retVal = CheckStateFormatLevel(rp, &stateFormatLevel, jsonProfileIsFromUser);
	    if (retVal != TPM_RC_SUCCESS)
		goto error;

            /* if user did not provide algo profile use the default one */
	    if (!algorithmsProfile && rp->algorithmsProfile) {
		algorithmsProfile = strdup(rp->algorithmsProfile);
		if (!algorithmsProfile) {
		    retVal = TPM_RC_MEMORY;
		    goto error;
		}
	    }
	    if (!commandsProfile && rp->commandsProfile) {
		commandsProfile = strdup(rp->commandsProfile);
		if (!commandsProfile) {
		    retVal = TPM_RC_MEMORY;
		    goto error;
		}
	    }

	    retVal = RuntimeProfileSetRuntimeProfile(RuntimeProfile, rp,
						     algorithmsProfile,
						     commandsProfile);
	    if (retVal != TPM_RC_SUCCESS)
		return retVal;
	    break;
	}
    }
    if (!rp) {
	retVal = TPM_RC_FAILURE;
	goto error;
    }

    retVal = RuntimeProfileFormat(&runtimeProfileJSON, profileName,
                                  stateFormatLevel, algorithmsProfile,
                                  commandsProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto error;

    TPMLIB_LogPrintf("%s @ %u: runtimeProfile: %s\n", __func__, __LINE__, runtimeProfileJSON);

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = runtimeProfileJSON;

    free(RuntimeProfile->RuntimeAlgorithm.algorithmProfile);
    RuntimeProfile->RuntimeAlgorithm.algorithmProfile = algorithmsProfile;

    free(RuntimeProfile->RuntimeCommands.commandsProfile);
    RuntimeProfile->RuntimeCommands.commandsProfile = commandsProfile;

    free(RuntimeProfile->profileName);
    RuntimeProfile->profileName = profileName;

    /* Indicate whether the profile was mapped to the default profile due to
     * a NULL pointer read from the state.
     */
    RuntimeProfile->wasNullProfile = (jsonProfile == NULL) && (jsonProfileIsFromUser == FALSE);
    /* Another way is if the user passed in the null profile */
    if (jsonProfileIsFromUser && !strcmp("null", profileName))
        RuntimeProfile->wasNullProfile = true;

    return TPM_RC_SUCCESS;

error:
    free(commandsProfile);
    free(algorithmsProfile);
    free(profileName);

    return retVal;
}

LIB_EXPORT const char *
RuntimeProfileGetJSON(
		      struct RuntimeProfile *RuntimeProfile
		      )
{
    return RuntimeProfile->runtimeProfileJSON;
}

LIB_EXPORT TPM_RC
RuntimeProfileTest(
		   struct RuntimeProfile *RuntimeProfile,
		   const char	         *jsonProfile,
		   bool                   jsonProfileIsFromUser
		   )
{
    const struct RuntimeProfileDesc *rp = NULL;
    char *algorithmsProfile = NULL;
    char *commandsProfile = NULL;
    unsigned int stateFormatLevel;
    char *profileName = NULL;
    char *oldProfile = NULL;
    TPM_RC retVal;
    size_t i;

    retVal = GetParametersFromJSON(jsonProfile, jsonProfileIsFromUser,
				   &profileName, &stateFormatLevel,
				   &algorithmsProfile, &commandsProfile);
    if (retVal != TPM_RC_SUCCESS)
	 return retVal;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    rp = &RuntimeProfileDescs[i];

	    retVal = CheckStateFormatLevel(rp, &stateFormatLevel,
	    				   jsonProfileIsFromUser);
	    if (retVal != TPM_RC_SUCCESS)
		goto error;

	    break;
	}
    }
    if (!rp) {
	retVal = TPM_RC_FAILURE;
	goto error;
    }

    if (algorithmsProfile) {
	/* Test the algorithms profile if one was given;
	 * The CommandProfile will be taken from the profile description above
	 * and is assumed to be correct.
	 */
	retVal = RuntimeAlgorithmSwitchProfile(&RuntimeProfile->RuntimeAlgorithm,
					       algorithmsProfile, &oldProfile);
	if (retVal == TPM_RC_SUCCESS)
	    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm,
	    					oldProfile);
    }

error:
    free(algorithmsProfile);
    free(profileName);

    return retVal;
}

LIB_EXPORT BOOL
RuntimeProfileWasNullProfile(
			     struct RuntimeProfile *RuntimeProfile
			     )
{
    return RuntimeProfile->wasNullProfile;
}
