// vmmyara.c : Implementation the YARA API wrapper for MemProcFS.
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmyara.h"
#include <yara.h>

#ifdef LINUX
#define _Out_writes_(x)
#define min(X,Y)                            ((X) < (Y) ? (X) : (Y))
#define max(X,Y)                            ((X) > (Y) ? (X) : (Y))
#define _TRUNCATE                           ((SIZE_T)-1LL)
#define fopen_s(ppFile, szFile, szAttr)     ((*ppFile = fopen64(szFile, szAttr)) ? 0 : 1)
#define strncpy_s(dst, len, src, srclen)    (strncpy(dst, src, min((long long unsigned int)(max(1, len)) - 1, (long long unsigned int)(srclen))))
#define strncat_s(dst, dstlen, src, srclen) (strncat(dst, src, min((((strlen(dst) + 1 >= (size_t)(dstlen)) || ((size_t)(dstlen) == 0)) ? 0 : ((size_t)(dstlen) - strlen(dst) - 1)), (size_t)(srclen))))
#define _snprintf_s(s,l,c,...)              (snprintf(s,min((size_t)(l), (size_t)(c)),__VA_ARGS__))
#endif /* LINUX */

int g_Initialized = 0;

#ifdef _WIN32
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ PVOID lpvReserved)
{
    int err;
    if(fdwReason == DLL_PROCESS_ATTACH) {
        err = yr_initialize();
        if(err) { return FALSE; }
        g_Initialized = 1;
    }
    if(fdwReason == DLL_PROCESS_DETACH) {
        if(g_Initialized) {
            yr_finalize();
        }
        g_Initialized = 0;
    }
    return TRUE;
}
#endif /* _WIN32 */
#ifdef LINUX
__attribute__((constructor)) VOID VmmYaraAttach()
{
    int err = yr_initialize();
    if(err) { return; }
    g_Initialized = 1;
}

__attribute__((destructor)) VOID VmmYaraDetach()
{
    if(g_Initialized) {
        yr_finalize();
    }
    g_Initialized = 0;
}
#endif /* LINUX */

/*
* Split the string usz into two at the last (back)slash which is removed.
* Ex: usz: XXX/YYY/ZZZ/AAA -> uszPath: XXX/YYY/ZZZ + return: AAA
* -- usz = utf-8 or ascii string.
* -- uszPath = buffer to receive result.
* -- cbuPath = byte length of uszPath buffer
* -- return
*/
LPSTR CharUtil_PathSplitLastEx(_In_ LPSTR usz, _Out_writes_(cbuPath) LPSTR uszPath, _In_ DWORD cbuPath)
{
    DWORD i, iSlash = -1;
    CHAR ch = -1;
    if(!cbuPath) { return NULL; }
    for(i = 0; ch && i < cbuPath; i++) {
        ch = usz[i];
        uszPath[i] = ch;
        if((ch == '\\') || (ch == '/')) {
            iSlash = i;
        }
    }
    uszPath[cbuPath - 1] = 0;
    if(iSlash == (DWORD)-1) { return NULL; }
    uszPath[iSlash] = 0;
    return uszPath + iSlash + 1;
}

LPSTR CharUtil_Trim(_In_ LPSTR s, _Out_writes_(cbBuffer) LPSTR szBuffer, _In_ DWORD cbBuffer)
{
    LPSTR p;
    if(!cbBuffer) { return ""; }
    szBuffer[0] = 0;
    if(!s || !*s || (cbBuffer <= strlen(s))) { ""; }
    strncpy_s(szBuffer, cbBuffer, s, _TRUNCATE);
    for(p = szBuffer + strlen(szBuffer) - 1; (p >= szBuffer) && isspace(*p); --p);
    p[1] = 0;
    return szBuffer;
}

/*
* Load a compiled yara rule file.
* -- szCompiledFileRules = the file path of the compiled yara rule file to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive the
*                    handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
EXPORTED_FUNCTION
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadCompiled(
    _In_ LPSTR szCompiledFileRules,
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    CHAR szBuffer[512];
    return yr_rules_load(CharUtil_Trim(szCompiledFileRules, szBuffer, sizeof(szBuffer)), (YR_RULES**)phVmmYaraRules);
}

/*
* Load one or multiple yara rules from source files.
* -- cszSourceFileRules = the number of source files to load.
* -- pszSourceFileRules = array of source file paths to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive the
*                    handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
EXPORTED_FUNCTION
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceFile(
    _In_ DWORD cszSourceFileRules,
    _In_reads_(cszSourceFileRules) LPSTR pszSourceFileRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    DWORD i;
    int err;
    FILE *hFile = 0;
    YR_COMPILER *pYrCompiler = NULL;
    CHAR szBuffer[512], szYaraRulesPath[512] = { 0 };
    *phVmmYaraRules = NULL;
    // 1: compiler init:
    err = yr_compiler_create(&pYrCompiler);
    if(err) { goto fail; }
    // 2: add all source files to compiler:
    for(i = 0; i < cszSourceFileRules; i++) {
        CharUtil_PathSplitLastEx(pszSourceFileRules[i], szYaraRulesPath, sizeof(szYaraRulesPath));
        strncat_s(szYaraRulesPath, sizeof(szYaraRulesPath), "/", _TRUNCATE);
        err = fopen_s(&hFile, CharUtil_Trim(pszSourceFileRules[i], szBuffer, sizeof(szBuffer)), "rt");
        if(err) {
            err = VMMYARA_ERROR_COULD_NOT_OPEN_FILE;
            goto fail;
        }
        err = yr_compiler_add_file(pYrCompiler, hFile, NULL, szYaraRulesPath);
        if(err) { goto fail; }
        if(hFile) { fclose(hFile); }
        hFile = 0;
    }
    // 3: retrieve rules:
    err = yr_compiler_get_rules(pYrCompiler, (YR_RULES**)phVmmYaraRules);
    if(err) { goto fail; }
    // fall-through to cleanup
fail:
    if(pYrCompiler) { yr_compiler_destroy(pYrCompiler); }
    if(hFile) { fclose(hFile); }
    return err;
}

/*
* Load one or multiple yara rules from in-memory source strings.
* -- cszSourceStringRules = the number of source strings to load.
* -- pszSourceStringRules = array of source strings to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive
*                    the handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
EXPORTED_FUNCTION
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceString(
    _In_ DWORD cszSourceStringRules,
    _In_reads_(cszSourceStringRules) LPSTR pszSourceStringRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    DWORD i;
    int err;
    YR_COMPILER *pYrCompiler = NULL;
    *phVmmYaraRules = NULL;
    // 1: compiler init:
    err = yr_compiler_create(&pYrCompiler);
    if(err) { goto fail; }
    // 2: add all source files to compiler:
    for(i = 0; i < cszSourceStringRules; i++) {
        err = yr_compiler_add_string(pYrCompiler, pszSourceStringRules[i], NULL);
        if(err) { goto fail; }
    }
    // 3: retrieve rules:
    err = yr_compiler_get_rules(pYrCompiler, (YR_RULES**)phVmmYaraRules);
    if(err) { goto fail; }
    // fall-through to cleanup
fail:
    if(pYrCompiler) { yr_compiler_destroy(pYrCompiler); }
    return err;
}

/*
* Load one or multiple yara rules from either memory or source files.
* -- cszSourceCombinedRules = the number of source files/strings to load.
* -- pszSourceCombinedRules = array of source file paths/strings to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive the
*                    handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
EXPORTED_FUNCTION
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceCombined(
    _In_ DWORD cszSourceCombinedRules,
    _In_reads_(cszSourceCombinedRules) LPSTR pszSourceCombinedRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
) {
    DWORD i;
    int err;
    FILE *hFile = 0;
    YR_COMPILER *pYrCompiler = NULL;
    CHAR szBuffer[512], szYaraRulesPath[512] = { 0 };
    *phVmmYaraRules = NULL;
    // 1: compiler init:
    err = yr_compiler_create(&pYrCompiler);
    if(err) { goto fail; }
    // 2: add all source files to compiler:
    for(i = 0; i < cszSourceCombinedRules; i++) {
        // try add as string:
        if(strstr(pszSourceCombinedRules[i], "{") && (strstr(pszSourceCombinedRules[i], "rule") || strstr(pszSourceCombinedRules[i], "RULE"))) {
            err = yr_compiler_add_string(pYrCompiler, pszSourceCombinedRules[i], NULL);
            if(err == VMMYARA_ERROR_SUCCESS) { continue; }
        }
        // try add as file:
        CharUtil_PathSplitLastEx(pszSourceCombinedRules[i], szYaraRulesPath, sizeof(szYaraRulesPath));
        strncat_s(szYaraRulesPath, sizeof(szYaraRulesPath), "/", _TRUNCATE);
        err = fopen_s(&hFile, CharUtil_Trim(pszSourceCombinedRules[i], szBuffer, sizeof(szBuffer)), "rt");
        if(err) {
            err = VMMYARA_ERROR_COULD_NOT_OPEN_FILE;
            goto fail;
        }
        err = yr_compiler_add_file(pYrCompiler, hFile, NULL, szYaraRulesPath);
        if(err) { goto fail; }
        if(hFile) { fclose(hFile); }
        hFile = 0;
    }
    // 3: retrieve rules:
    err = yr_compiler_get_rules(pYrCompiler, (YR_RULES**)phVmmYaraRules);
    if(err) { goto fail; }
    // fall-through to cleanup
fail:
    if(pYrCompiler) { yr_compiler_destroy(pYrCompiler); }
    if(hFile) { fclose(hFile); }
    return err;
}

/*
* Destroy a previously loaded rule set.
* -- hVmmYaraRules = the handle to the rule set to destroy.
*/
EXPORTED_FUNCTION
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesDestroy(_In_ PVMMYARA_RULES hVmmYaraRules)
{
    return yr_rules_destroy((YR_RULES*)hVmmYaraRules);
}

/*
* Internal callback context.
*/
typedef struct tdVMMYARA_SCANMEMORY_CALLBACK_CONTEXT {
    PBYTE pbBuffer;
    SIZE_T cbBuffer;
    PVOID pvContext;
    VMMYARA_SCAN_MEMORY_CALLBACK pfnCallback;
} VMMYARA_SCANMEMORY_CALLBACK_CONTEXT, *PVMMYARA_SCANMEMORY_CALLBACK_CONTEXT;

/*
* Internal yara callback function.
*/
int VmmYara_ScanMemoryCB(YR_SCAN_CONTEXT *context, int message, YR_RULE *rule, PVMMYARA_SCANMEMORY_CALLBACK_CONTEXT pContextCB)
{
    DWORD dwo;
    BOOL fResult;
    CHAR szIntegerBuffer[32 * VMMYARA_RULE_MATCH_META_MAX];
    VMMYARA_RULE_MATCH RuleMatch = { 0 };
    if(message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }
    // 1: rule identifier:
    RuleMatch.dwVersion = VMMYARA_RULE_MATCH_VERSION;
    RuleMatch.szRuleIdentifier = (LPSTR)rule->identifier;
    // 2: tags:
    const char *tag = NULL;
    yr_rule_tags_foreach(rule, tag)
    {
        if(RuleMatch.cTags >= VMMYARA_RULE_MATCH_TAG_MAX) {
            break;
        }
        RuleMatch.szTags[RuleMatch.cTags] = (LPSTR)tag;
        RuleMatch.cTags++;
    }
    // 3: meta:
    YR_META *meta = NULL;
    yr_rule_metas_foreach(rule, meta)
    {
        if(RuleMatch.cMeta >= VMMYARA_RULE_MATCH_META_MAX) {
            break;
        }
        RuleMatch.Meta[RuleMatch.cMeta].szIdentifier = (LPSTR)meta->identifier;
        if(meta->type == META_TYPE_STRING) {
            RuleMatch.Meta[RuleMatch.cMeta].szString = (LPSTR)meta->string;
        } else if(meta->type == META_TYPE_INTEGER) {
            dwo = RuleMatch.cMeta * 32;
            szIntegerBuffer[dwo] = 0;
            _snprintf_s(szIntegerBuffer + dwo, 32, _TRUNCATE, "%lli", (long long int)meta->integer);
            RuleMatch.Meta[RuleMatch.cMeta].szString = szIntegerBuffer + dwo;
        } else if(meta->type == META_TYPE_BOOLEAN) {
            RuleMatch.Meta[RuleMatch.cMeta].szString = meta->integer ? "true" : "false";
        } else {
            continue;
        }
        RuleMatch.cMeta++;
    }
    // 4: matching strings and offsets:
    YR_STRING *string = NULL;
    yr_rule_strings_foreach(rule, string)
    {
        if(RuleMatch.cStrings >= VMMYARA_RULE_MATCH_STRING_MAX) {
            break;
        }
        YR_MATCH *match = NULL;
        yr_string_matches_foreach(context, string, match) {
            if(RuleMatch.Strings[RuleMatch.cStrings].cMatch >= VMMYARA_RULE_MATCH_OFFSET_MAX) {
                break;
            }
            RuleMatch.Strings[RuleMatch.cStrings].cbMatchOffset[RuleMatch.Strings[RuleMatch.cStrings].cMatch] = (SIZE_T)match->offset;
            RuleMatch.Strings[RuleMatch.cStrings].cMatch++;
        }
        if(RuleMatch.Strings[RuleMatch.cStrings].cMatch) {
            RuleMatch.Strings[RuleMatch.cStrings].szString = (LPSTR)string->string;
            RuleMatch.cStrings++;
        }
    }
    // callback:
    fResult = pContextCB->pfnCallback(pContextCB->pvContext, &RuleMatch, pContextCB->pbBuffer, pContextCB->cbBuffer);
    // return:
    return fResult ? CALLBACK_CONTINUE : CALLBACK_ABORT;
}

/*
* Scan a memory buffer for matches against the specified rule set.
* Upon a match the callback function will be called with the match information.
* -- hVmmYaraRules = the handle to the rule set to scan against.
* -- pbBuffer = the memory buffer to scan.
* -- cbBuffer = the size of the memory buffer to scan.
* -- flags = flags according to yr_rules_scan_mem() to use.
* -- pfnCallback = the callback function to call upon a match.
* -- pvContext = context to pass to the callback function.
* -- timeout = timeout in seconds according to yr_rules_scan_mem().
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
EXPORTED_FUNCTION
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_ScanMemory(
    _In_ PVMMYARA_RULES hVmmYaraRules,
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ SIZE_T cbBuffer,
    _In_ int flags,
    _In_ VMMYARA_SCAN_MEMORY_CALLBACK pfnCallback,
    _In_ PVOID pvContext,
    _In_ int timeout
) {
    VMMYARA_SCANMEMORY_CALLBACK_CONTEXT ctx = { pbBuffer, cbBuffer, pvContext, pfnCallback };
    return yr_rules_scan_mem(
        (YR_RULES*)hVmmYaraRules,
        pbBuffer,
        cbBuffer,
        flags | SCAN_FLAGS_REPORT_RULES_MATCHING,
        (YR_CALLBACK_FUNC)VmmYara_ScanMemoryCB,
        &ctx,
        timeout
    );
}
