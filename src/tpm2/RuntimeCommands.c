/********************************************************************************/
/*										*/
/*			 TPM 2 Commands Runtime Disablement 			*/
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

#include <errno.h>

#include "Tpm.h"
#include "tpm_library_intern.h"

#if VENDOR_COMMAND_COUNT != 0
# error Vendor commands not supported
#endif


/* List of supported commands sorted by command codes */
static const struct {
    const char *name;
} s_CommandProperties[NUM_ENTRIES_COMMAND_PROPERTIES] = {
#define COMMAND(NAME) \
    [ CcToIdx(TPM_CC_ ## NAME) ] = { .name = CC_ ## NAME ? STRINGIFY(NAME) : NULL }
    COMMAND(NV_UndefineSpaceSpecial),
    COMMAND(EvictControl),
    COMMAND(HierarchyControl),
    COMMAND(NV_UndefineSpace),
    COMMAND(ChangeEPS),
    COMMAND(ChangePPS),
    COMMAND(Clear),
    COMMAND(ClearControl),
    COMMAND(ClockSet),
    COMMAND(HierarchyChangeAuth),
    COMMAND(NV_DefineSpace),
    COMMAND(PCR_Allocate),
    COMMAND(PCR_SetAuthPolicy),
    COMMAND(PP_Commands),
    COMMAND(SetPrimaryPolicy),
    COMMAND(FieldUpgradeStart),
    COMMAND(ClockRateAdjust),
    COMMAND(CreatePrimary),
    COMMAND(NV_GlobalWriteLock),
    COMMAND(GetCommandAuditDigest),
    COMMAND(NV_Increment),
    COMMAND(NV_SetBits),
    COMMAND(NV_Extend),
    COMMAND(NV_Write),
    COMMAND(NV_WriteLock),
    COMMAND(DictionaryAttackLockReset),
    COMMAND(DictionaryAttackParameters),
    COMMAND(NV_ChangeAuth),
    COMMAND(PCR_Event),
    COMMAND(PCR_Reset),
    COMMAND(SequenceComplete),
    COMMAND(SetAlgorithmSet),
    COMMAND(SetCommandCodeAuditStatus),
    COMMAND(FieldUpgradeData),
    COMMAND(IncrementalSelfTest),
    COMMAND(SelfTest),
    COMMAND(Startup),
    COMMAND(Shutdown),
    COMMAND(StirRandom),
    COMMAND(ActivateCredential),
    COMMAND(Certify),
    COMMAND(PolicyNV),
    COMMAND(CertifyCreation),
    COMMAND(Duplicate),
    COMMAND(GetTime),
    COMMAND(GetSessionAuditDigest),
    COMMAND(NV_Read),
    COMMAND(NV_ReadLock),
    COMMAND(ObjectChangeAuth),
    COMMAND(PolicySecret),
    COMMAND(Rewrap),
    COMMAND(Create),
    COMMAND(ECDH_ZGen),
    COMMAND(MAC),
    /* HMAC is same as MAC */
    COMMAND(Import),
    COMMAND(Load),
    COMMAND(Quote),
    COMMAND(RSA_Decrypt),
    COMMAND(MAC_Start),
    /* HMAC_start is same as MAC_Start */
    COMMAND(SequenceUpdate),
    COMMAND(Sign),
    COMMAND(Unseal),
    COMMAND(PolicySigned),
    COMMAND(ContextLoad),
    COMMAND(ContextSave),
    COMMAND(ECDH_KeyGen),
    COMMAND(EncryptDecrypt),
    COMMAND(FlushContext),
    COMMAND(LoadExternal),
    COMMAND(MakeCredential),
    COMMAND(NV_ReadPublic),
    COMMAND(PolicyAuthorize),
    COMMAND(PolicyAuthValue),
    COMMAND(PolicyCommandCode),
    COMMAND(PolicyCounterTimer),
    COMMAND(PolicyCpHash),
    COMMAND(PolicyLocality),
    COMMAND(PolicyNameHash),
    COMMAND(PolicyOR),
    COMMAND(PolicyTicket),
    COMMAND(ReadPublic),
    COMMAND(RSA_Encrypt),
    COMMAND(StartAuthSession),
    COMMAND(VerifySignature),
    COMMAND(ECC_Parameters),
    COMMAND(FirmwareRead),
    COMMAND(GetCapability),
    COMMAND(GetRandom),
    COMMAND(GetTestResult),
    COMMAND(Hash),
    COMMAND(PCR_Read),
    COMMAND(PolicyPCR),
    COMMAND(PolicyRestart),
    COMMAND(ReadClock),
    COMMAND(PCR_Extend),
    COMMAND(PCR_SetAuthValue),
    COMMAND(NV_Certify),
    COMMAND(EventSequenceComplete),
    COMMAND(HashSequenceStart),
    COMMAND(PolicyPhysicalPresence),
    COMMAND(PolicyDuplicationSelect),
    COMMAND(PolicyGetDigest),
    COMMAND(TestParms),
    COMMAND(Commit),
    COMMAND(PolicyPassword),
    COMMAND(ZGen_2Phase),
    COMMAND(EC_Ephemeral),
    COMMAND(PolicyNvWritten),
    COMMAND(PolicyTemplate),
    COMMAND(CreateLoaded),
    COMMAND(PolicyAuthorizeNV),
    COMMAND(EncryptDecrypt2),
    COMMAND(AC_GetCapability),
    COMMAND(AC_Send),
    COMMAND(Policy_AC_SendSelect),
    COMMAND(CertifyX509),
    COMMAND(ACT_SetTimeout),
    COMMAND(ECC_Encrypt),
    COMMAND(ECC_Decrypt),
#undef COMMAND
};

static void
RuntimeCommandsEnableAllCommands(
				 struct RuntimeCommands *RuntimeCommands
				 )
{
    COMMAND_INDEX commandIndex;

    MemorySet(RuntimeCommands->enabledCommands, 0 , sizeof(RuntimeCommands->enabledCommands));

    for (commandIndex = 0; commandIndex < ARRAY_SIZE(s_CommandProperties); commandIndex++) {
	/* skip over unsupported commands */
	if (!s_CommandProperties[commandIndex].name)
	    continue;
	SET_BIT(IdxToCc(commandIndex), RuntimeCommands->enabledCommands);
    }
}

LIB_EXPORT void
RuntimeCommandsInit(
		    struct RuntimeCommands *RuntimeCommands
		    )
{
    MemorySet(RuntimeCommands, 0, sizeof(*RuntimeCommands));
}

LIB_EXPORT void
RuntimeCommandsFree(
		    struct RuntimeCommands *RuntimeCommands
		    )
{
    free(RuntimeCommands->commandsProfile);
    RuntimeCommands->commandsProfile = NULL;
}

/* Set the default profile with all commands enabled */
static void
RuntimeCommandsSetDefault(
			  struct RuntimeCommands *RuntimeCommands
			  )
{
    free(RuntimeCommands->commandsProfile);
    RuntimeCommands->commandsProfile = NULL;
    RuntimeCommandsInit(RuntimeCommands);
    RuntimeCommandsEnableAllCommands(RuntimeCommands);
}

static int
parseRange(const char *buffer, size_t buflen,
	   TPM_CC *commandCodeLo, TPM_CC *commandCodeHi)
{
    char *endptr;
    unsigned long v;

    errno = 0;
    v = strtoul(buffer, &endptr, 0);
    if (errno != 0)
	return -1;
    if (v > (unsigned int)~0)
	return -1;
    *commandCodeLo = v;

    if (endptr[0] == '-') {
	v = strtoul(&endptr[1], &endptr, 0);
	if (errno != 0)
	    return -1;
	if (v > (unsigned int)~0)
	    return -1;
	*commandCodeHi = v;
    } else {
	*commandCodeHi = *commandCodeLo;
    }

    if (endptr[0] != ',' && endptr[0] != '\0')
	return -1;

    return 0;
}

/* Set the given profile and runtime-enable the given commands. A NULL pointer
 * for the profile command sets the default profile which enables all commands.
 */
LIB_EXPORT
TPM_RC
RuntimeCommandsSetProfile(
			  struct RuntimeCommands *RuntimeCommands,
			  const char		 *newProfile  // IN: comma-separated list of command codes and ranges
			  )
{
    TPM_CC commandCodeLo, commandCodeHi;
    TPM_RC retVal = TPM_RC_VALUE;
    const char *token, *comma;
    COMMAND_INDEX commandIndex;
    size_t toklen;

    TPMLIB_LogPrintf("%s: new profile: %s\n", __func__, newProfile);

    /* NULL pointer for profile enables all */
    if (!newProfile) {
	RuntimeCommandsSetDefault(RuntimeCommands);
	return TPM_RC_SUCCESS;
    }

    MemorySet(&RuntimeCommands->enabledCommands, 0, sizeof(RuntimeCommands->enabledCommands));

    token = newProfile;
    while (1) {
	/* expecting: 20 or 0x32 or 20-30 or 0x30x-0x50 */
	comma = strchr(token, ',');
	if (comma)
	    toklen = (size_t)(comma - token);
	else
	    toklen = strlen(token);

	if (parseRange(token, toklen, &commandCodeLo, &commandCodeHi) < 0) {
	    TPMLIB_LogTPM2Error("Requested command range %.*s cannot be parsed.\n",
				(int)toklen, token);
	    goto exit;
	}
	if (CcToIdx(commandCodeLo) >= ARRAY_SIZE(s_CommandProperties) ||
	    CcToIdx(commandCodeHi) >= ARRAY_SIZE(s_CommandProperties)) {
	    TPMLIB_LogTPM2Error("Requested command range %.*s is invalid.\n",
				(int)toklen, token);
	    goto exit;
	}
	for (commandIndex = CcToIdx(commandCodeLo);
	     commandIndex <= CcToIdx(commandCodeHi);
	     commandIndex++) {
	    /* must not select unsupported commands */
	    if (!s_CommandProperties[commandIndex].name) {
		TPMLIB_LogTPM2Error("Requested command code 0x%x is not implemented.\n",
				    IdxToCc(commandIndex));
		goto exit;
	    }
	    SET_BIT(IdxToCc(commandIndex), RuntimeCommands->enabledCommands);
	}

	if (!comma)
	    break;
	token = &comma[1];
    }
    retVal = TPM_RC_SUCCESS;

exit:
    if (retVal != TPM_RC_SUCCESS)
	RuntimeCommandsSetDefault(RuntimeCommands);

    return retVal;
}

/* Check whether the given command is runtime-disabled */
LIB_EXPORT BOOL
RuntimeCommandsCheckEnabled(
			    struct RuntimeCommands *RuntimeCommands,
			    TPM_CC	            commandCode      // IN: the commandCode to check
			    )
{
    TPMLIB_LogPrintf("IsEnEnabled(0x%x = '%s'): %d\n",
		     commandCode,
		     s_CommandProperties[CcToIdx(commandCode)].name,
		     TEST_BIT(commandCode, RuntimeCommands->enabledCommands));
    if (!TEST_BIT(commandCode, RuntimeCommands->enabledCommands))
	return FALSE;
    return TRUE;
}

/* Get the number of enabled commands. */
LIB_EXPORT UINT32
RuntimeCommandsCountEnabled(
			    struct RuntimeCommands *RuntimeCommands
			    )
{
    TPM_CC commandCode;
    UINT32 count = 0;

    for (commandCode = TPM_CC_First;
	 commandCode < sizeof(RuntimeCommands->enabledCommands) * 8;
	 commandCode++) {
	if (TEST_BIT(commandCode, RuntimeCommands->enabledCommands))
	    count++;
    }
    return count;
}