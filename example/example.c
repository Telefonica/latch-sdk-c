
#include "../latch.h"
#include <stdio.h>

int main()
{

	const char *AppId = "APP_ID";
	const char *SecretKey = "SECRET_KEY";
	const char *ClientWallet = "CLIENT_WALLET";
	const char *ClientSignature = "CLIENT_SIGNATURE";
	const char *AccountId = "ACCOUNT_ID";
	const char *OperationId = "	OPERATION_ID";
	const char *AccountNameId = "account@email.com";

	init(AppId, SecretKey);

	char *responsePairId, *responsePair, *responseStatus, *responseStatusOperation, *responseUnpair, *responseLock,  *responseLockOperation, *responseUnlock;

 	responsePairId = pairWithId(AccountNameId);

	printf("%s\n", responsePairId);

	responsePair = pair("pairCode");

	printf("%s\n", responsePair);

	responseStatus = status(AccountId);

	printf("%s\n", responseStatus);

	responseStatusOperation = statusOperation(AccountId, OperationId);

	printf("%s\n", responseStatusOperation);

	responseLock = lock(AccountId);

	printf("%s\n", responseLock);

	responseLockOperation = lockOperation(AccountId, OperationId);

	printf("%s\n", responseLockOperation);

	responseUnlock = unlock(AccountId);

	printf("%s\n", responseUnlock);

	responseUnpair = unpair(AccountId);

	printf("%s\n", responseUnpair);

	return 0;
}
