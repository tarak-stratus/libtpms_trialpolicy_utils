/********************************************************************************/
/*										*/
/*			       Runtime Profile 					*/
/*			     Written by Stefan Berger				*/
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
#include <stdio.h>
#include <regex.h>

#include "Tpm.h"
#include "tpm_library_intern.h"

struct RuntimeProfile g_RuntimeProfile;

static const struct RuntimeProfileDesc {
    const char *name;
    const char *commandProfile;
} RuntimeProfileDescs[] = {
    {
	.name = "default",
	.commandProfile = NULL,
    }, {
	.name = "fips",
	.commandProfile = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
    }, {
	.name = "1",
	.commandProfile = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
    }, {
	.name = NULL
    }
};

LIB_EXPORT TPM_RC
RuntimeProfileInit(
		   struct RuntimeProfile           *RuntimeProfile
		   )
{
    RuntimeAlgorithmInit(&RuntimeProfile->RuntimeAlgorithm);
    RuntimeCommandsInit(&RuntimeProfile->RuntimeCommands);

    return TPM_RC_SUCCESS;
}

static TPM_RC
RuntimeProfileSetRuntimeProfile(
                                struct RuntimeProfile           *RuntimeProfile,
				const struct RuntimeProfileDesc *rp,
				const char                      *algorithmsProfile
				)
{
    TPM_RC retVal;

    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm, algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    return RuntimeCommandsSetProfile(&RuntimeProfile->RuntimeCommands, rp->commandProfile);
}

static TPM_RC
RuntimeProfileGetFromJSON(
			  const char  *json,
			  const char  *regex,
			  char       **value
			  )
{
    regmatch_t match[2];
    regex_t r;

    if (regcomp(&r, regex, REG_EXTENDED) != 0)
	return TPM_RC_FAILURE;

    if (regexec(&r, json, 2, match, 0) == REG_NOMATCH)
	return TPM_RC_NO_RESULT;

    if (match[1].rm_eo - match[1].rm_so == 0)
	return TPM_RC_SIZE;

    *value = strndup(&json[match[1].rm_so], match[1].rm_eo - match[1].rm_so);
    if (*value == NULL)
	return TPM_RC_MEMORY;

    return TPM_RC_SUCCESS;
}

static TPM_RC
RuntimeProfileGetNameFromJSON(
			      const char  *json,
			      char       **name
			      )
{
    const char *regex = "^\\{[[:space:]]*\"name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*";

    return RuntimeProfileGetFromJSON(json, regex, name);
}

static TPM_RC
GetAlgorithmsProfileFromJSON(
			     const char  *json,
			     char       **algorithmsProfile
			     )
{
    const char *regex = ".*,[[:space:]]*\"algorithms\"[[:space:]]*:[[:space:]]*\"([^\"]+)\"";
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, algorithmsProfile);
    if (retVal == TPM_RC_NO_RESULT) {
        *algorithmsProfile = NULL;
        retVal = 0;
    }
    return retVal;
}

static TPM_RC
GetParametersFromJSON(
		      const char *json,
		      char       **profileName,
		      const char  *defaultProfile,
		      char       **algorithmsProfile
		      )
{
    TPM_RC retVal;

    if (!json) {
	*profileName = strdup(defaultProfile);
	if (*profileName == NULL)
	    return TPM_RC_MEMORY;
	return TPM_RC_SUCCESS;
    }

    retVal = RuntimeProfileGetNameFromJSON(json, profileName);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    return GetAlgorithmsProfileFromJSON(json, algorithmsProfile);
}

static TPM_RC
RuntimeProfileFormat(char **json, const char *profileName, const char *algorithmsProfile)
{
    const struct RuntimeProfileDesc *rp = NULL;
    char *ret, *nret;
    size_t i;
    int n;

    if (!profileName)
        return TPM_RC_SUCCESS;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    rp = &RuntimeProfileDescs[i];
	    break;
	}
    }
    if (!rp)
        return TPM_RC_FAILURE;

    n = asprintf(&ret, "{\"name\":\"%s\"", profileName);
    if (n < 0)
        return TPM_RC_MEMORY;
    if (rp->commandProfile) {
        n = asprintf(&nret, "%s,\"commands\":\"%s\"", ret, rp->commandProfile);
        if (n < 0) {
            free(ret);
            return TPM_RC_MEMORY;
        }
        ret = nret;
    }
    if (algorithmsProfile) {
        n = asprintf(&nret, "%s,\"algorithms\":\"%s\"", ret, algorithmsProfile);
        if (n < 0) {
            free(ret);
            return TPM_RC_MEMORY;
        }
        ret = nret;
    }
    n = asprintf(&nret, "%s}", ret);
    if (n < 0) {
       free(ret);
       return TPM_RC_MEMORY;
    }
    *json = nret;

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
RuntimeProfileSet(
                  struct RuntimeProfile *RuntimeProfile,
		  const char            *json
		  )
{
    char *runtimeProfileJSON = NULL;
    char *algorithmsProfile = NULL;
    char *profileName = NULL;
    TPM_RC retVal;
    size_t i;

    retVal = GetParametersFromJSON(json,
				   &profileName, "default",
				   &algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    retVal = RuntimeProfileSetRuntimeProfile(RuntimeProfile,
						     &RuntimeProfileDescs[i],
						     algorithmsProfile);
            if (retVal != TPM_RC_SUCCESS)
                return retVal;
	    break;
	}
    }

    /* Do not format the runtime profile if no JSON was provided and 
     * have RuntimeProfileGet return a NULL pointer.
     */
    if (json) {
	retVal = RuntimeProfileFormat(&runtimeProfileJSON, profileName, algorithmsProfile);
	if (retVal != TPM_RC_SUCCESS)
	    return retVal;
    }

    TPMLIB_LogPrintf("%s @ %u: runtimeProfile: %s\n", __func__, __LINE__, runtimeProfileJSON);

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = runtimeProfileJSON;

    free(RuntimeProfile->RuntimeAlgorithm.algorithmProfile); // FIXME: use a function
    RuntimeProfile->RuntimeAlgorithm.algorithmProfile = algorithmsProfile;

    free(RuntimeProfile->profileName);
    RuntimeProfile->profileName = profileName;

    return TPM_RC_SUCCESS;
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
		   const char	    *json
		   )
{
    const struct RuntimeProfileDesc *rp = NULL;
    char *algorithmsProfile = NULL;
    char *profileName = NULL;
    char *oldProfile = NULL;
    TPM_RC retVal;
    size_t i;

    retVal = GetParametersFromJSON(json,
				   &profileName, "default",
				   &algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	 return retVal;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    rp = &RuntimeProfileDescs[i];
	    break;
	}
    }
    if (!rp)
	return TPM_RC_FAILURE;

    if (algorithmsProfile) {
	/* test the algorithms profile if one was given */
	retVal = RuntimeAlgorithmSwitchProfile(&RuntimeProfile->RuntimeAlgorithm,
					       algorithmsProfile, &oldProfile);
	if (retVal == TPM_RC_SUCCESS)
	    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm, oldProfile);
    }

    free(algorithmsProfile);
    free(profileName);

    return retVal;
}
