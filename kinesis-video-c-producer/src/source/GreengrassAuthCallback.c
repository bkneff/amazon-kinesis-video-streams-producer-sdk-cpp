/**
 * Kinesis Video Producer GreengrassCredential Auth Callback
 */
#define LOG_CLASS "GreengrassAuthCallbacks"
#include "Include_i.h"

/*
 * Create Greengrass credentials callback
 */
STATUS createGreengrassAuthCallbacks(PClientCallbacks pCallbacksProvider,
                             PAuthCallbacks *ppGreengrassAuthCallbacks)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    PGreengrassAuthCallbacks pGreengrassAuthCallbacks = NULL;

    CHK(pCallbacksProvider != NULL && ppGreengrassAuthCallbacks != NULL
        , STATUS_NULL_ARG);

    // Allocate the entire structure
    pGreengrassAuthCallbacks = (PGreengrassAuthCallbacks) MEMCALLOC(1, SIZEOF(GreengrassAuthCallbacks));
    CHK(pGreengrassAuthCallbacks != NULL, STATUS_NOT_ENOUGH_MEMORY);

    // Set the version, self
    pGreengrassAuthCallbacks->authCallbacks.version = AUTH_CALLBACKS_CURRENT_VERSION;
    pGreengrassAuthCallbacks->authCallbacks.customData = (UINT64) pGreengrassAuthCallbacks;

    // Store the back pointer as we will be using the other callbacks
    pGreengrassAuthCallbacks->pCallbacksProvider = (PCallbacksProvider) pCallbacksProvider;

    // Set the callbacks
    pGreengrassAuthCallbacks->authCallbacks.getStreamingTokenFn = getStreamingTokenGreengrassFunc;
    pGreengrassAuthCallbacks->authCallbacks.getSecurityTokenFn = getSecurityTokenGreengrassFunc;
    pGreengrassAuthCallbacks->authCallbacks.freeAuthCallbacksFn = freeGreengrassAuthCallbacksFunc;
    pGreengrassAuthCallbacks->authCallbacks.getDeviceCertificateFn = NULL;
    pGreengrassAuthCallbacks->authCallbacks.deviceCertToTokenFn = NULL;
    pGreengrassAuthCallbacks->authCallbacks.getDeviceFingerprintFn = NULL;

    CHK_STATUS(greengrassCurlHandler(pGreengrassAuthCallbacks));

    CHK_STATUS(addAuthCallbacks(pCallbacksProvider, (PAuthCallbacks) pGreengrassAuthCallbacks));

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        freeGreengrassAuthCallbacks((PAuthCallbacks*) &pGreengrassAuthCallbacks);
        pGreengrassAuthCallbacks = NULL;
    }
    // Set the return value if it's not NULL
    if (ppGreengrassAuthCallbacks != NULL) {
        *ppGreengrassAuthCallbacks = (PAuthCallbacks) pGreengrassAuthCallbacks;
    }

    LEAVES();
    return retStatus;
}

/**
 * Frees the GreengrassCredential Auth callback object
 *
 * NOTE: The caller should have passed a pointer which was previously created by the corresponding function
 */
STATUS freeGreengrassAuthCallbacks(PAuthCallbacks* ppGreengrassAuthCallbacks)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    //TODO abort ongoing request if free is called.

    PGreengrassAuthCallbacks pGreengrassAuthCallbacks = NULL;

    CHK(ppGreengrassAuthCallbacks != NULL, STATUS_NULL_ARG);

    pGreengrassAuthCallbacks = (PGreengrassAuthCallbacks) *ppGreengrassAuthCallbacks;

    // Call is idempotent
    CHK(pGreengrassAuthCallbacks != NULL, retStatus);

    curl_easy_cleanup(pGreengrassAuthCallbacks->curl);

    // Release the underlying AWS credentials object
    if (pGreengrassAuthCallbacks->pAwsCredentials != NULL) {
        freeAwsCredentials(&pGreengrassAuthCallbacks->pAwsCredentials);
    }

    if (pGreengrassAuthCallbacks->responseData != NULL) {
        MEMFREE(pGreengrassAuthCallbacks->responseData);
    }

    // Release the object
    MEMFREE(pGreengrassAuthCallbacks);

    // Set the pointer to NULL
    *ppGreengrassAuthCallbacks = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS freeGreengrassAuthCallbacksFunc(PUINT64 customData)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PGreengrassAuthCallbacks pAuthCallbacks;

    CHK(customData != NULL, STATUS_NULL_ARG);
    pAuthCallbacks = (PGreengrassAuthCallbacks) *customData;
    CHK_STATUS(freeGreengrassAuthCallbacks((PAuthCallbacks*) &pAuthCallbacks));

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS getStreamingTokenGreengrassFunc(UINT64 customData, PCHAR streamName, STREAM_ACCESS_MODE accessMode,
                                PServiceCallContext pServiceCallContext)
{
    UNUSED_PARAM(streamName);
    UNUSED_PARAM(accessMode);
    UINT64 currentTime;

    ENTERS();
    STATUS retStatus = STATUS_SUCCESS, status = STATUS_SUCCESS;
    PGreengrassAuthCallbacks pGreengrassAuthCallbacks = (PGreengrassAuthCallbacks) customData;

    CHK(pGreengrassAuthCallbacks != NULL, STATUS_NULL_ARG);

    // Refresh the credentials by calling Greengrass endpoint if needed
    currentTime = pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.getCurrentTimeFn(
            pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.customData);
    if (currentTime + GREENGRASS_CREDENTIAL_FETCH_GRACE_PERIOD > pGreengrassAuthCallbacks->pAwsCredentials->expiration) {
        CHK_STATUS(greengrassCurlHandler(pGreengrassAuthCallbacks));
    }

CleanUp:

    status = getStreamingTokenResultEvent(pServiceCallContext->customData,
                                          STATUS_SUCCEEDED(retStatus) ? SERVICE_CALL_RESULT_OK : SERVICE_CALL_UNKNOWN,
                                          (PBYTE) pGreengrassAuthCallbacks->pAwsCredentials,
                                          pGreengrassAuthCallbacks->pAwsCredentials->size,
                                          pGreengrassAuthCallbacks->pAwsCredentials->expiration);

    if (!STATUS_SUCCEEDED(status) &&
        pGreengrassAuthCallbacks->pCallbacksProvider->pStreamCallbacks->streamErrorReportFn != NULL) {
        pGreengrassAuthCallbacks->pCallbacksProvider->pStreamCallbacks->streamErrorReportFn(
                pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.customData,
                INVALID_STREAM_HANDLE_VALUE,
                INVALID_UPLOAD_HANDLE_VALUE,
                0,
                status);
    }

    LEAVES();
    return retStatus;
}

STATUS getSecurityTokenGreengrassFunc(UINT64 customData, PBYTE *ppBuffer, PUINT32 pSize, PUINT64 pExpiration)
{

    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 currentTime;

    PGreengrassAuthCallbacks pGreengrassAuthCallbacks = (PGreengrassAuthCallbacks) customData;
    CHK(pGreengrassAuthCallbacks != NULL && ppBuffer != NULL && pSize != NULL && pExpiration != NULL,
        STATUS_NULL_ARG);

    // Refresh the credentials by calling Greengrass endpoint if needed
    currentTime = pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.getCurrentTimeFn(
            pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.customData);
    if (currentTime + GREENGRASS_CREDENTIAL_FETCH_GRACE_PERIOD > pGreengrassAuthCallbacks->pAwsCredentials->expiration) {
        CHK_STATUS(greengrassCurlHandler(pGreengrassAuthCallbacks));
    }

    *pExpiration = pGreengrassAuthCallbacks->pAwsCredentials->expiration;
    *pSize = pGreengrassAuthCallbacks->pAwsCredentials->size;
    *ppBuffer = (PBYTE) pGreengrassAuthCallbacks->pAwsCredentials;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS parseGreengrassResponse(PGreengrassAuthCallbacks pGreengrassAuthCallbacks)
{

    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    UINT32 i, resultLen, accessKeyIdLen = 0, secretKeyLen = 0, sessionTokenLen = 0, expirationTimestampLen = 0;
    INT32 tokenCount;
    jsmn_parser parser;
    jsmntok_t tokens[MAX_JSON_TOKEN_COUNT];
    PCHAR accessKeyId = NULL, secretKey = NULL, sessionToken = NULL, expirationTimestamp = NULL, pResponseStr = NULL;
    UINT64 expiration, currentTime;
    CHAR expirationTimestampStr[MAX_EXPIRATION_LEN + 1];

    CHK(pGreengrassAuthCallbacks != NULL, STATUS_NULL_ARG);

    resultLen = pGreengrassAuthCallbacks->responseDataLen;
    pResponseStr = pGreengrassAuthCallbacks->responseData;
    CHK(resultLen > 0, STATUS_GREENGRASS_FAILED);

    jsmn_init(&parser);
    tokenCount = jsmn_parse(&parser, pResponseStr, resultLen, tokens, SIZEOF(tokens) / SIZEOF(jsmntok_t));

    CHK(tokenCount > 1, STATUS_INVALID_API_CALL_RETURN_JSON);
    CHK(tokens[0].type == JSMN_OBJECT, STATUS_INVALID_API_CALL_RETURN_JSON);

    for (i = 1; i < tokenCount; i++) {
        if (compareJsonString(pResponseStr, &tokens[i], JSMN_STRING, (PCHAR) "AccessKeyId")) {
            accessKeyIdLen = (UINT32) (tokens[i + 1].end - tokens[i + 1].start);
            CHK(accessKeyIdLen <= MAX_ACCESS_KEY_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
            accessKeyId = pResponseStr + tokens[i + 1].start;
            i++;
        } else if (compareJsonString(pResponseStr, &tokens[i], JSMN_STRING, (PCHAR) "SecretAccessKey")) {
            secretKeyLen = (UINT32) (tokens[i + 1].end - tokens[i + 1].start);
            CHK(secretKeyLen <= MAX_SECRET_KEY_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
            secretKey = pResponseStr + tokens[i + 1].start;
            i++;
        } else if (compareJsonString(pResponseStr, &tokens[i], JSMN_STRING, (PCHAR) "Token")) {
            sessionTokenLen = (UINT32) (tokens[i + 1].end - tokens[i + 1].start);
            CHK(sessionTokenLen <= MAX_SESSION_TOKEN_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
            sessionToken = pResponseStr + tokens[i + 1].start;
            i++;
        } else if (compareJsonString(pResponseStr, &tokens[i], JSMN_STRING, "Expiration")) {
            expirationTimestampLen = (UINT32) (tokens[i + 1].end - tokens[i + 1].start);
            CHK(expirationTimestampLen <= MAX_EXPIRATION_LEN, STATUS_INVALID_API_CALL_RETURN_JSON);
            expirationTimestamp = pResponseStr + tokens[i + 1].start;
            MEMCPY(expirationTimestampStr, expirationTimestamp, expirationTimestampLen);
            expirationTimestampStr[expirationTimestampLen] = '\0';
            i++;
        }
    }

    CHK(accessKeyId != NULL && secretKey != NULL && sessionToken != NULL, STATUS_GREENGRASS_FAILED);

    currentTime = pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.getCurrentTimeFn(
            pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.customData);
    CHK_STATUS(convertTimestampToEpoch(expirationTimestampStr, currentTime / HUNDREDS_OF_NANOS_IN_A_SECOND, &expiration));
    DLOGD("Greengrass credential expiration time %" PRIu64, expiration / HUNDREDS_OF_NANOS_IN_A_SECOND);

    if (pGreengrassAuthCallbacks->pAwsCredentials != NULL) {
        freeAwsCredentials(&pGreengrassAuthCallbacks->pAwsCredentials);
        pGreengrassAuthCallbacks->pAwsCredentials = NULL;
    }

    // Fix-up the expiration to be no more than max enforced token rotation to avoid extra token rotations
    // as we are caching the returned value which is likely to be an hour but we are enforcing max
    // rotation to be more frequent.
    expiration = MIN(expiration, currentTime + MAX_ENFORCED_TOKEN_EXPIRATION_DURATION);


    CHK_STATUS(createAwsCredentials(accessKeyId,
                                    accessKeyIdLen,
                                    secretKey,
                                    secretKeyLen,
                                    sessionToken,
                                    sessionTokenLen,
                                    expiration,
                                    &pGreengrassAuthCallbacks->pAwsCredentials));

CleanUp:

    LEAVES();
    return retStatus;
}

SIZE_T writeGreengrassResponseCallback(PCHAR pBuffer, SIZE_T size, SIZE_T numItems, PVOID customData)
{
    PGreengrassAuthCallbacks pGreengrassAuthCallbacks = (PGreengrassAuthCallbacks) customData;

    // Does not include the NULL terminator
    SIZE_T dataSize = size * numItems;

    if (pGreengrassAuthCallbacks == NULL) {
        return CURL_READFUNC_ABORT;
    }

    // Alloc and copy if needed
    PCHAR pNewBuffer = pGreengrassAuthCallbacks->responseData == NULL ?
                       (PCHAR) MEMALLOC(pGreengrassAuthCallbacks->responseDataLen + dataSize + SIZEOF(CHAR)) :
                       (PCHAR) REALLOC(pGreengrassAuthCallbacks->responseData,
                                       pGreengrassAuthCallbacks->responseDataLen + dataSize + SIZEOF(CHAR));
    if (pNewBuffer != NULL) {
        // Append the new data
        MEMCPY((PBYTE)pNewBuffer + pGreengrassAuthCallbacks->responseDataLen, pBuffer, dataSize);

        pGreengrassAuthCallbacks->responseData = pNewBuffer;
        pGreengrassAuthCallbacks->responseDataLen += dataSize;
        pGreengrassAuthCallbacks->responseData[pGreengrassAuthCallbacks->responseDataLen] = '\0';
    } else {
        return CURL_READFUNC_ABORT;
    }

    return dataSize;
}

STATUS greengrassCurlHandler(PGreengrassAuthCallbacks pGreengrassAuthCallbacks)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    CURL* curl = NULL;
    CURLcode res;
    PCHAR url;
    LONG httpStatusCode;
    CHAR errorBuffer[CURL_ERROR_SIZE];
    errorBuffer[0] = '\0';
    UINT64 authStrLen = GREENGRASS_MAX_AUTH_HEADER_LENGTH, currentTime;
    UINT32 formatLen = 0;
    CHAR auth[GREENGRASS_MAX_AUTH_HEADER_LENGTH];
    PCHAR serviceUrl = NULL;
    PCHAR ggAuthToken = NULL;

    if ((serviceUrl = getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")) == NULL ) {
        DLOGE("Greengrass credential endpoint is not set");
        CHK(FALSE, STATUS_GREENGRASS_FAILED);
    }

    if ((ggAuthToken = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")) == NULL ) {
        DLOGE("Greengrass auth token is not set");
        CHK(FALSE, STATUS_GREENGRASS_FAILED);
    }

    struct curl_slist* headerList = NULL;

    currentTime = pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.getCurrentTimeFn(
            pGreengrassAuthCallbacks->pCallbacksProvider->clientCallbacks.customData);
    // check if existing pAwsCredential is still valid.
    CHK(pGreengrassAuthCallbacks->pAwsCredentials == NULL ||
        (currentTime + MIN_STREAMING_TOKEN_EXPIRATION_DURATION) >= pGreengrassAuthCallbacks->pAwsCredentials->expiration, retStatus);
    CHK(pGreengrassAuthCallbacks->curl == NULL, STATUS_INTERNAL_ERROR);
    curl = pGreengrassAuthCallbacks->curl;

    // old responseData will be freed at next curl write data call
    pGreengrassAuthCallbacks->responseDataLen = 0;

    formatLen = SNPRINTF(auth, authStrLen, "%s%s", "Authorization:", ggAuthToken);

    CHK(formatLen > 0 && formatLen < authStrLen, STATUS_GREENGRASS_FAILED);

    // CURL global initialization
    CHK(0 == curl_global_init(CURL_GLOBAL_ALL), STATUS_CURL_LIBRARY_INIT_FAILED);
    curl = curl_easy_init();
    CHK(curl != NULL, STATUS_CURL_INIT_FAILED);

    headerList = curl_slist_append(headerList, auth);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
    curl_easy_setopt(curl, CURLOPT_URL, serviceUrl);
    //curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, GREENGRASS_CERT_TYPE);
    //curl_easy_setopt(curl, CURLOPT_SSLCERT, pGreengrassAuthCallbacks->certPath);
    //curl_easy_setopt(curl, CURLOPT_SSLKEY, pGreengrassAuthCallbacks->privateKeyPath);
    //curl_easy_setopt(curl, CURLOPT_CAINFO, pGreengrassAuthCallbacks->caCertPath);
    //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeGreengrassResponseCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pGreengrassAuthCallbacks);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, REQUEST_COMPLETION_TIMEOUT_MS);

    // Setting up limits for curl timeout
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, CURLOPT_LOW_SPEED_TIME_VALUE);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, CURLOPT_LOW_SPEED_LIMIT_VALUE);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
        DLOGE("Greengrass curl perform failed for url %s with result %s : %s ", url, curl_easy_strerror(res), errorBuffer);
        CHK(FALSE, STATUS_GREENGRASS_FAILED);
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpStatusCode);
    CHK_ERR(httpStatusCode == HTTP_STATUS_CODE_OK, STATUS_GREENGRASS_FAILED, "Greengrass get credential response http status %lu was not ok", httpStatusCode);
    CHK_STATUS(parseGreengrassResponse(pGreengrassAuthCallbacks));

CleanUp:

    if (headerList != NULL) {
        curl_slist_free_all(headerList);
        curl_easy_cleanup(curl);
        pGreengrassAuthCallbacks->curl = NULL;
    }

    return retStatus;
}
