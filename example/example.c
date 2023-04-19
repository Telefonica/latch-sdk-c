
#include "../latch.h"
#include <stdio.h>

int main()
{

	const char *AppId = "APP_ID";
	const char *SecretKey = "SECRET_KEY";

	init(AppId, SecretKey);

	char *responsePairId, *responsePair, *responseStatus, *responseUnpair, *responseLock, *responseUnlock;

	responsePairId = pairWithId("test@email.com");

	printf("%s\n", responsePairId);

	responsePair = pair("pairCode");

	printf("%s\n", responsePair);

	responseLock = lock("accountId");

	printf("%s\n", responseLock);

	responseUnlock = unlock("accountId");

	printf("%s\n", responseUnlock);

	responseStatus = status("accountId");

	printf("%s\n", responseStatus);

	responseUnpair = unpair("accountId");

	printf("%s\n", responseUnpair);

	return 0;
}
