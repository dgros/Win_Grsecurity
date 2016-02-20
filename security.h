#ifndef _SECURITY_
#define _SECURITY_

#include "driver.h"


typedef struct object_droit {
	unsigned long name;
	char droit[20];
	struct object_droit * Next ;
} Object;

unsigned long  hash_function(char * str);
char * GetPolicy(char * dos_name, char * temp, int count);
Object * AddInStruct(unsigned long hash, char * droit,  Object * structure);




#endif