/*
 * This library implements all functions of Latch API.
 * Copyright (C) 2013 Eleven Paths

 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define AUTHORIZATION_HEADER_NAME "Authorization"
#define DATE_HEADER_NAME "X-11Paths-Date"
#define AUTHORIZATION_METHOD "11PATHS"
#define AUTHORIZATION_HEADER_FIELD_SEPARATOR " "
#define UTC_STRING_FORMAT "%Y-%m-%d %H:%M:%S"

#define API_CHECK_STATUS_URL "/api/0.9/status"
#define API_PAIR_URL "/api/0.9/pair"
#define API_PAIR_WITH_ID_URL "/api/0.9/pairWithId"
#define API_UNPAIR_URL "/api/0.9/unpair"
#define API_LOCK_URL "/api/0.9/lock"
#define API_UNLOCK_URL "/api/0.9/unlock"
#define API_HISTORY_URL "/api/0.9/history"
#define API_OPERATION_URL "/api/0.9/operation"

#define HTTP_METHOD_GET "GET"
#define HTTP_METHOD_POST "POST"
#define HTTP_METHOD_PUT "PUT"
#define HTTP_METHOD_DELETE "DELETE"

#define HTTP_PARAM_LOCK_ON_REQUEST "lock_on_request"
#define HTTP_PARAM_NAME "name"
#define HTTP_PARAM_PARENTID "parentId"
#define HTTP_PARAM_TWO_FACTOR "two_factor"

typedef struct curl_response_buffer {
    char *buffer;
    size_t size;
} curl_response_buffer;

/*
 * Function to handle stuff from HTTP response.
 * 
 * @param buf- Raw buffer from libcurl.
 * @param len- number of indexes
 * @param size- size of each index
 * @param userdata- any extra user data needed
 * @return Number of bytes actually handled. If different from len * size, curl will throw an error
 */
static int writeFn(void* buf, size_t len, size_t size, void* userdata) {

    size_t realsize = len * size;
    curl_response_buffer *response = (curl_response_buffer*)userdata;

    response->buffer = realloc(response->buffer, response->size + realsize + 1);

    memcpy(&(response->buffer[response->size]), buf, realsize);
    response->size += realsize;
    response->buffer[response->size] = '\0';

    return realsize;

}

/*
 * Function to encode a string in Base64 format
 * 
 * @param input- string to encode
 * @param length- string length
 * @return encoded string in Base64 format
 */

char* base64encode(const unsigned char *input, int length) {
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length - 1);
	buff[bptr->length - 1] = 0;

	BIO_free_all(b64);

	return buff;
}

char toHex(char code) {
    static char hex[] = "0123456789ABCDEF";
    return hex[code & 15];
}

/*
 * Function to percent-encode a string
 *
 * Based on http://www.geekhideout.com/downloads/urlcode.c
 */
char* urlEncode(const char* str, int space2Plus) {

    char* buf = NULL;
    char* pbuf = NULL;
    const char* pstr = str;

    if ((str != NULL) && ((buf = malloc(strlen(str) * 3 + 1)) != NULL)) {
        pbuf = buf;
        while (*pstr) {
            if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
                *pbuf++ = *pstr;
            } else if (*pstr == ' ' && space2Plus) {
                *pbuf++ = '+';
            } else {
                *pbuf++ = '%';
                *pbuf++ = toHex(*pstr >> 4);
                *pbuf++ = toHex(*pstr & 15);
            }
            pstr++;
        }
        *pbuf = '\0';
    }

    return buf;

}

/*
 * Function to calculate the HMAC hash (SHA1) of a string. Returns a Base64 value of the hash
 * 
 * @param pSecretKey- secret key
 * @param pData- original data to calculate the HMAC
 * @return HMAC in Base64 format
 */
char* sign_data(const char* pSecretKey, const char* pData) {
    unsigned char* digest;

    digest = HMAC(EVP_sha1(), pSecretKey, strlen(pSecretKey), (unsigned char*) pData, strlen(pData), NULL, NULL);
    return base64encode(digest, 20);
}

int nosignal = 0;
int timeout = 2;
const char* AppId;
const char* SecretKey;
const char* Host = "https://latch.elevenpaths.com";
const char* Proxy;
const char* tlsCAFile = NULL;
const char* tlsCAPath = NULL;
const char* tlsCRLFile = NULL;

void init(const char* pAppId, const char* pSecretKey) {
	AppId = pAppId;
	SecretKey = pSecretKey;
}

void setHost(const char* pHost){
	Host = pHost;
}

/*
 * Enable using a Proxy to connect to Latch Server
 */
void setProxy(const char* pProxy){
	Proxy = pProxy;
}

void setTimeout(const int iTimeout)
{
    timeout = iTimeout;
}

/*
 * If called with iNoSignal 1, CURLOPT_NOSIGNAL will be set to 1
 */
void setNoSignal(const int iNoSignal)
{
    nosignal = iNoSignal;
}

void setTLSCAFile(const char* pTLSCAFile)
{
    tlsCAFile = pTLSCAFile;
}

void setTLSCAPath(const char* pTLSCAPath)
{
    tlsCAPath = pTLSCAPath;
}

void setTLSCRLFile(const char* pTLSCRLFile)
{
    tlsCRLFile = pTLSCRLFile;
}

void authenticationHeaders(const char* pHTTPMethod, const char* pQueryString, char* pHeaders[], const char *pBody) {

	char* authHeader, *dateHeader, *stringToSign, *b64hash;
	char utc[20];
	time_t timer;
	struct tm tm_info;
	int len = 0;

	time(&timer);
	gmtime_r(&timer, &tm_info);
	strftime(utc, 20, UTC_STRING_FORMAT, &tm_info);

	if (pBody == NULL) {
	    len = strlen(pHTTPMethod) + strlen(utc) + strlen(pQueryString) + 4;
	} else {
	    len = strlen(pHTTPMethod) + strlen(utc) + strlen(pQueryString) + strlen(pBody) + 5;
	}

	stringToSign = malloc(len);

	if (pBody == NULL) {
	    snprintf(stringToSign, len, "%s\n%s\n\n%s", pHTTPMethod, utc, pQueryString);
	} else {
	    snprintf(stringToSign, len, "%s\n%s\n\n%s\n%s", pHTTPMethod, utc, pQueryString, pBody);
	}

	b64hash = sign_data(SecretKey, stringToSign);

	len = strlen(AUTHORIZATION_HEADER_NAME) + strlen(AUTHORIZATION_METHOD) + strlen(AppId) + strlen(b64hash) + 5;
	authHeader = malloc(len);
	snprintf(authHeader, len, "%s: %s %s %s", AUTHORIZATION_HEADER_NAME, AUTHORIZATION_METHOD, AppId, b64hash);

	len = strlen(DATE_HEADER_NAME) + strlen(utc) + 3;
	dateHeader = malloc(len);
	snprintf(dateHeader, len, "%s: %s", DATE_HEADER_NAME, utc);

	pHeaders[0] = authHeader;
	pHeaders[1] = dateHeader;

    free(stringToSign);
    free(b64hash);

}

/*
 * Perform a GET request to the specified URL of the Latch API
 * @param pUrl- requested URL including host
 */
char* http_proxy(const char* pMethod, const char* pUrl, const char* pBody) {

	char* headers[2];
	curl_response_buffer response;
	char error_message[CURL_ERROR_SIZE];
	CURL* pCurl = curl_easy_init();
	int res = -1;
	int i = 0;
	struct curl_slist* chunk = NULL;
	char* hostAndUrl;
	
	if (!pCurl) {
		return NULL;
	}

    response.buffer = malloc(1*sizeof(char));
    response.size = 0;
    response.buffer[response.size] = '\0';

	authenticationHeaders(pMethod, pUrl, headers, pBody);
	for (i=0; i<(sizeof(headers)/sizeof(char*)); i++) {
		chunk = curl_slist_append(chunk, headers[i]);
	}

    free(headers[0]);
    free(headers[1]);

	hostAndUrl = malloc(strlen(Host) + strlen(pUrl) + 1);
	strcpy(hostAndUrl, Host);
	strcat(hostAndUrl, pUrl);

	curl_easy_setopt(pCurl, CURLOPT_URL, hostAndUrl);
	curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
	curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &response);
	curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
	curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 1);

	curl_easy_setopt(pCurl, CURLOPT_CUSTOMREQUEST, pMethod);

	if (strcmp(pMethod, HTTP_METHOD_POST) == 0 || strcmp(pMethod, HTTP_METHOD_PUT)) {
	    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pBody);
	    if (pBody == NULL) {
	        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, 0);
	    }
	}

	if(Proxy != NULL){
		curl_easy_setopt(pCurl, CURLOPT_PROXY, Proxy);
	}

	// we don't want to leave our user waiting at the login prompt forever
	curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, timeout);

	// SSL needs 16k of random stuff. We'll give it some space in RAM.
	curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1);
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

	// error message when curl_easy_perform return non-zero
	curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, error_message);

	// Optional if setNoSignal(1)
	// Avoid crashing if multithread, DNS timeout and libcurl < 7.32.0
	// Blocks with standard resolver (doesn't apply the timeout)

	if (nosignal == 1) {
	    curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1);
	}

	if (tlsCAFile != NULL) {
	    curl_easy_setopt(pCurl, CURLOPT_CAINFO, tlsCAFile);
	    curl_easy_setopt(pCurl, CURLOPT_CAPATH, NULL);
	}
	else {
	    if (tlsCAPath != NULL) {
	        curl_easy_setopt(pCurl, CURLOPT_CAINFO, NULL);
	        curl_easy_setopt(pCurl, CURLOPT_CAPATH, tlsCAPath);
	    }
	}

	if (tlsCRLFile != NULL) {
	    curl_easy_setopt(pCurl, CURLOPT_CRLFILE, tlsCRLFile);
	}

	// synchronous, but we don't really care
	res = curl_easy_perform(pCurl);

	curl_easy_cleanup(pCurl);
    curl_slist_free_all(chunk);
    free(hostAndUrl);

    if (res != CURLE_OK) {
        free(response.buffer);
        return NULL;
    }
    else {
        return response.buffer;
    }

}

char* buildURLWithOneParameter(const char* pBase, const char* pParameter) {

    char* rv = NULL;
    char* encodedParameter = NULL;

    if (pBase != NULL && pParameter != NULL) {
        encodedParameter = urlEncode(pParameter, 0);
        if (pParameter != NULL) {
            if ((rv = malloc((strlen(pBase) + 1 + strlen(encodedParameter) + 1) * sizeof(char))) != NULL) {
                snprintf(rv, strlen(pBase) + 1 + strlen(encodedParameter) + 1, "%s/%s", pBase, encodedParameter);
            }
            free(encodedParameter);
        }
    }

    return rv;

}

char* buildURLWithTwoParameters(const char* pBase, const char* pParameter1, const char* pSeparator, const char* pParameter2) {

    char *urlA = NULL;
    char *urlB = NULL;
    char *encodedParameter2 = NULL;

    if (pBase != NULL && pParameter1 != NULL && pParameter2 != NULL) {
        urlA = buildURLWithOneParameter(pBase, pParameter1);
        if (urlA != NULL) {
            encodedParameter2 = urlEncode(pParameter2, 0);
            if (encodedParameter2 != NULL) {
                if ((urlB = malloc((strlen(urlA) + 1 + strlen(pSeparator) + 1 + strlen(encodedParameter2) + 1) * sizeof(char))) != NULL) {
                    snprintf(urlB, strlen(urlA) + 1 + strlen(pSeparator) + 1 + strlen(encodedParameter2) + 1, "%s/%s/%s", urlA, pSeparator, encodedParameter2);
                }
                free(encodedParameter2);
            }
            free(urlA);
        }
    }

    return urlB;

}

char* buildURLWithAccountIdAndFromAndTo(const char* pBase, const char* pAccountId, time_t from, time_t to) {

    char *urlA = NULL;
    char *urlB = NULL;

    if (pBase != NULL && pAccountId != NULL) {
        urlA = buildURLWithOneParameter(pBase, pAccountId);
        if (urlA != NULL) {
            if ((urlB = malloc((strlen(urlA) + 1 + 13 + 1 + 13 + 1) * sizeof(char))) != NULL) {
                snprintf(urlB, strlen(urlA) + 1 + 13 + 1 + 13 + 1, "%s/%d000/%d000", urlA, from, to);
            }
            free(urlA);
        }
    }

    return urlB;

}

char* oneParameterOperation(const char* pBase, const char* pParameter, const char* pMethod) {

    char *response = NULL;
    char *url = NULL;

    if (pParameter != NULL) {
        url = buildURLWithOneParameter(pBase, pParameter);
        if (url != NULL) {
            response = http_proxy(pMethod, url, NULL);
            free(url);
        }
    }

    return response;

}

char* twoParameterOperation(const char* pBase, const char* pParameter1, const char* pSeparator, const char* pParameter2, const char* pMethod) {

    char *response = NULL;
    char *url = NULL;

    if (pParameter1 != NULL && pParameter2 != NULL) {
        url = buildURLWithTwoParameters(pBase, pParameter1, pSeparator, pParameter2);
        if (url != NULL) {
            response = http_proxy(pMethod, url, NULL);
            free(url);
        }
    }

    return response;

}

char* pairWithId(const char* pAccountId) {
    return oneParameterOperation(API_PAIR_WITH_ID_URL, pAccountId, HTTP_METHOD_GET);
}

char* pair(const char* pToken) {
    return oneParameterOperation(API_PAIR_URL, pToken, HTTP_METHOD_GET);
}

char* status(const char* pAccountId) {
    return oneParameterOperation(API_CHECK_STATUS_URL, pAccountId, HTTP_METHOD_GET);
}

char* operationStatus(const char* pAccountId, const char* pOperationId) {
    return twoParameterOperation(API_CHECK_STATUS_URL, pAccountId, "op", pOperationId, HTTP_METHOD_GET);
}

char* unpair(const char* pAccountId) {
    return oneParameterOperation(API_UNPAIR_URL, pAccountId, HTTP_METHOD_GET);
}

char* lock(const char* pAccountId) {
    return oneParameterOperation(API_LOCK_URL, pAccountId, HTTP_METHOD_POST);
}

char* operationLock(const char* pAccountId, const char* pOperationId) {
    return twoParameterOperation(API_LOCK_URL, pAccountId, "op", pOperationId, HTTP_METHOD_POST);
}

char* unlock(const char* pAccountId) {
    return oneParameterOperation(API_UNLOCK_URL, pAccountId, HTTP_METHOD_POST);
}

char* operationUnlock(const char* pAccountId, const char* pOperationId) {
    return twoParameterOperation(API_UNLOCK_URL, pAccountId, "op", pOperationId, HTTP_METHOD_POST);
}

char* history(const char* pAccountId) {
    return oneParameterOperation(API_HISTORY_URL, pAccountId, HTTP_METHOD_GET);
}

char* timePeriodHistory(const char* pAccountId, time_t from, time_t to) {

    char *response = NULL;
    char *url = NULL;

    if (pAccountId != NULL) {
        url = buildURLWithAccountIdAndFromAndTo(API_HISTORY_URL, pAccountId, from, to);
        if (url != NULL) {
            response = http_proxy(HTTP_METHOD_GET, url, NULL);
            free(url);
        }
    }

    return response;
}

char* operationCreate(const char* pParentId, const char* pName, const char* pTwoFactor, const char* pLockOnRequest) {

    char *response = NULL;
    char *encodedParentId = NULL;
    char *encodedName = NULL;
    char *encodedTwoFactor = NULL;
    char *encodedLockOnRequest = NULL;
    char *body = NULL;
    int bodyLength = 0;

    if (pParentId != NULL && pName != NULL) {

        encodedParentId = urlEncode(pParentId, 1);
        encodedName = urlEncode(pName, 1);

        if (pTwoFactor != NULL) {
            encodedTwoFactor = urlEncode(pTwoFactor, 1);
        }

        if (pLockOnRequest != NULL) {
            encodedLockOnRequest = urlEncode(pLockOnRequest, 1);
        }

        if (pLockOnRequest != NULL) {
            bodyLength += strlen(HTTP_PARAM_LOCK_ON_REQUEST) + 1 + strlen(encodedLockOnRequest); /* name=value */
            bodyLength += 1; /* & */
        }

        bodyLength += strlen(HTTP_PARAM_NAME) + 1 + strlen(encodedName); /* name=value */
        bodyLength += 1; /* & */
        bodyLength += strlen(HTTP_PARAM_PARENTID) + 1 + strlen(encodedParentId); /* name=value */

        if (pTwoFactor != NULL) {
            bodyLength += 1; /* & */
            bodyLength += strlen(HTTP_PARAM_TWO_FACTOR) + 1 + strlen(encodedTwoFactor); /* name=value */
        }

        bodyLength += 1; /* NULL */

        if ((body = malloc(bodyLength * sizeof(char))) != NULL) {

            *body = '\0';

            if (pLockOnRequest != NULL) {
                strcat(body, HTTP_PARAM_LOCK_ON_REQUEST);
                strcat(body, "=");
                strcat(body, encodedLockOnRequest);
                strcat(body, "&");
            }

            strcat(body, HTTP_PARAM_NAME);
            strcat(body, "=");
            strcat(body, encodedName);
            strcat(body, "&");
            strcat(body, HTTP_PARAM_PARENTID);
            strcat(body, "=");
            strcat(body, encodedParentId);

            if (pTwoFactor != NULL) {
                strcat(body, "&");
                strcat(body, HTTP_PARAM_TWO_FACTOR);
                strcat(body, "=");
                strcat(body, encodedTwoFactor);
            }

            response = http_proxy(HTTP_METHOD_PUT, API_OPERATION_URL, body);

        }

        free(body);
        free(encodedParentId);
        free(encodedName);
        free(encodedTwoFactor);
        free(encodedLockOnRequest);

    }

    return response;

}

char* operationUpdate(const char* pOperationId, const char* pName, const char* pTwoFactor, const char* pLockOnRequest) {

    char *response = NULL;
    char *encodedOperationId = NULL;
    char *encodedName = NULL;
    char *encodedTwoFactor = NULL;
    char *encodedLockOnRequest = NULL;
    char *url;
    char *body = NULL;
    int bodyLength = 0;
    int first = 1;
    int parameters = 0;

    if (pOperationId != NULL && (pName != NULL || pTwoFactor != NULL || pLockOnRequest != NULL)) {

        encodedOperationId = urlEncode(pOperationId, 1);

        if (pName != NULL) {
            encodedName = urlEncode(pName, 1);
        }

        if (pTwoFactor != NULL) {
            encodedTwoFactor = urlEncode(pTwoFactor, 1);
        }

        if (pLockOnRequest != NULL) {
            encodedLockOnRequest = urlEncode(pLockOnRequest, 1);
        }

        url = buildURLWithOneParameter(API_OPERATION_URL, encodedOperationId);

        if (pLockOnRequest != NULL) {
            bodyLength += strlen(HTTP_PARAM_LOCK_ON_REQUEST) + 1 + strlen(encodedLockOnRequest); /* name=value */
            parameters++;
        }

        if (pName != NULL) {
            bodyLength += strlen(HTTP_PARAM_NAME) + 1 + strlen(encodedName); /* name=value */
            parameters++;
        }

        if (pTwoFactor != NULL) {
            bodyLength += strlen(HTTP_PARAM_TWO_FACTOR) + 1 + strlen(encodedTwoFactor); /* name=value */
            parameters++;
        }

        bodyLength += parameters - 1 + 1; /* &s AND NULL */

        if ((body = malloc(bodyLength * sizeof(char))) != NULL) {

            *body = '\0';

            if (pLockOnRequest != NULL) {
                strcat(body, HTTP_PARAM_LOCK_ON_REQUEST);
                strcat(body, "=");
                strcat(body, encodedLockOnRequest);
                first = 0;
            }

            if (pName != NULL) {
                if (!first) {
                    strcat(body, "&");
                }
                strcat(body, HTTP_PARAM_NAME);
                strcat(body, "=");
                strcat(body, encodedName);
                first = 0;
            }

            if (pTwoFactor != NULL) {
                if (!first) {
                    strcat(body, "&");
                }
                strcat(body, HTTP_PARAM_TWO_FACTOR);
                strcat(body, "=");
                strcat(body, encodedTwoFactor);
            }

            response = http_proxy(HTTP_METHOD_POST, url, body);

        }

        free(body);
        free(url);
        free(encodedOperationId);
        free(encodedName);
        free(encodedTwoFactor);
        free(encodedLockOnRequest);

    }

    return response;

}

char* operationRemove(const char* pOperationId) {
    return oneParameterOperation(API_OPERATION_URL, pOperationId, HTTP_METHOD_DELETE);
}
