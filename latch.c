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


#include "latch.h"

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
	char *response_ptr =  (char *)userdata;	
	size_t needed = size * len;
	
	if (needed > LATCH_BUFFER_SIZE - 1) {
		/* Error, we cannot allocate so much info, but we will allocate the info that it fits */
		memcpy(response_ptr, buf, LATCH_BUFFER_SIZE - 1);
	} else {
		memcpy(response_ptr, buf, needed);
	}

	return needed;
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

	char *buff = (char *)malloc(bptr->length + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;

	BIO_free_all(b64);

	return buff;
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
	
	digest = HMAC(EVP_sha1(), pSecretKey, strlen(pSecretKey), (unsigned char*)pData, strlen(pData), NULL, NULL);
	return base64encode(digest, 20);
}


const char* AppId;
const char* SecretKey;
const char* Host = "https://latch.elevenpaths.com";
const char* Proxy;

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

void authenticationHeaders(const char* pHTTPMethod, const char* pQueryString, char* pHeaders[]) {
	char* authHeader, *dateHeader, *stringToSign, *b64hash;
	char utc[20];
	time_t timer;
	struct tm* tm_info;
	int len = 0;

	time(&timer);
	tm_info = localtime(&timer);
	strftime(utc, 20, UTC_STRING_FORMAT, tm_info);

	len = strlen(pHTTPMethod) + strlen(utc) + 4 + strlen(pQueryString);
	stringToSign = malloc(len);
	snprintf(stringToSign, len, "%s\n%s\n\n%s", pHTTPMethod, utc, pQueryString);

	b64hash = sign_data(SecretKey, stringToSign);

	len = strlen(AUTHORIZATION_HEADER_NAME) + strlen(AUTHORIZATION_METHOD) + strlen(AppId) + strlen(b64hash) + 4;
	authHeader = malloc(len);
	snprintf(authHeader, len, "%s: %s %s %s", AUTHORIZATION_HEADER_NAME, AUTHORIZATION_METHOD, AppId, b64hash);

	len = strlen(DATE_HEADER_NAME) + 3 + strlen(utc);
	dateHeader = malloc(len);
	snprintf(dateHeader, len, "%s: %s", DATE_HEADER_NAME, utc);

	pHeaders[0] = authHeader;
	pHeaders[1] = dateHeader;
}

/*
 * Perform a GET request to the specified URL of the Latch API
 * @param pUrl- requested URL including host
 */
char* http_get_proxy(const char* pUrl) {
	char* headers[2];
	char* response = malloc(LATCH_BUFFER_SIZE);
	char* errorResponse = malloc(LATCH_BUFFER_SIZE);
	CURL* pCurl = curl_easy_init();
	int res = -1;
	int i = 0;
	int timeOut = 1;	
	struct curl_slist* chunk = NULL;
	char* hostAndUrl;
	
	if (!pCurl) {
		return NULL;
	}

	authenticationHeaders("GET", pUrl, headers);
	for (i=0; i<(sizeof(headers)/sizeof(char*)); i++) {
		chunk = curl_slist_append(chunk, headers[i]);
	}

	hostAndUrl = malloc(strlen(Host) + strlen(pUrl) + 1);
	strcpy(hostAndUrl, Host);
	strcat(hostAndUrl, pUrl);

	curl_easy_setopt(pCurl, CURLOPT_URL, hostAndUrl);
	curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
	curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
	curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 1);

	if(Proxy != NULL){
		curl_easy_setopt(pCurl, CURLOPT_PROXY, Proxy); 
		timeOut = 2; 
	}

	// we don't want to leave our user waiting at the login prompt forever
	curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, timeOut);

	// SSL needs 16k of random stuff. We'll give it some space in RAM.
	curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

	// error message when curl_easy_perform return non-zero
	curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, errorResponse);


	// synchronous, but we don't really care
	res = curl_easy_perform(pCurl);

	curl_easy_cleanup(pCurl);

	return response;
}


char* pairWithId(const char* pAccountId) {
	char* url = malloc(strlen(API_PAIR_WITH_ID_URL) + strlen(pAccountId) + 2);
	strcpy(url, API_PAIR_WITH_ID_URL);
	strcat(url, "/");
	strcat(url, pAccountId);
	return http_get_proxy(url);
}

char* pair(const char* pToken) {
	char* url = malloc(strlen(API_PAIR_URL) + strlen(pToken) + 2);
	strcpy(url, API_PAIR_URL);
	strcat(url, "/");
	strcat(url, pToken);
	return http_get_proxy(url);
}

char* status(const char* pAccountId) {
	char* url = malloc(strlen(API_CHECK_STATUS_URL) + strlen(pAccountId) + 2);
	strcpy(url, API_CHECK_STATUS_URL);
	strcat(url, "/");
	strcat(url, pAccountId);
	return http_get_proxy(url);
}

char* operationStatus(const char* pAccountId, const char* pOperationId) {
	char* url = malloc(strlen(API_CHECK_STATUS_URL) + strlen(pAccountId) + strlen(pOperationId) + 6);
	strcpy(url, API_CHECK_STATUS_URL);
	strcat(url, "/");
	strcat(url, pAccountId);
	strcat(url, "/op/");
	strcat(url, pOperationId);
	return http_get_proxy(url);
}

char* unpair(const char* pAccountId) {
	char* url = malloc(strlen(API_UNPAIR_URL) + strlen(pAccountId) + 2);
	strcpy(url, API_UNPAIR_URL);
	strcat(url, "/");
	strcat(url, pAccountId);
	printf("%s\n\n", url);
	return http_get_proxy(url);
}
