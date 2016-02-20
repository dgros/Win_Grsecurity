#include "security.h"
unsigned long hash_table[20];
Object * objet[20];
int index_tableau =0;

int LoadPolicy()
{
	int status = 0, i=0, j=0,k,l, taille, compteur =0;
	unsigned long hash;
	NTSTATUS rc;
	HANDLE handle;
	char dos_name[100];
	char * temp;
	Object * parcours;
	OBJECT_ATTRIBUTES objatt;
	char *toto;
	PVOID buffer;
	IO_STATUS_BLOCK iostatus;
	WCHAR                  filepolicy[]  = L"\\??\\C:\\politique.txt"; 
	UNICODE_STRING         filepolicy_unicode; 
	FILE_STANDARD_INFORMATION fileobj;
	
	
	RtlInitUnicodeString (&filepolicy_unicode, filepolicy);
	InitializeObjectAttributes(&objatt, &filepolicy_unicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	rc = ZwCreateFile(&handle, FILE_ALL_ACCESS, &objatt, &iostatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF,  FILE_SYNCHRONOUS_IO_NONALERT, NULL,0);
	
	if(rc != STATUS_SUCCESS)
		return 1;	
	rc = ZwQueryInformationFile(handle,&iostatus,&fileobj,sizeof(fileobj),FileStandardInformation);
	
	if(rc != STATUS_SUCCESS)
		return 1;	
	
	taille = fileobj.EndOfFile.u.LowPart;
	buffer = ExAllocatePool(PagedPool, fileobj.EndOfFile.u.LowPart);
	toto =(char *) ExAllocatePool(PagedPool, fileobj.EndOfFile.u.LowPart);
	if(buffer != NULL)
	{
		rc = ZwReadFile(handle,NULL, NULL, NULL, &iostatus, buffer, taille, 0, NULL);//fileobj.EndOfFile.u.LowPart
		if(rc != STATUS_SUCCESS)
			return 1;
		if(toto == NULL)
			return 1;
		 sprintf(toto,"%s",buffer);
		 
	}
	
	ZwClose(handle);

	// Recherche du dos_name
	RtlZeroMemory(&dos_name, 100);
	temp = strstr(toto,"$set");
	if(temp != NULL )
	{
		i = i+5;
		while(temp[i] != '\n') 
		{
			dos_name[j] = temp[i];
			j++;
			i++;
		}
		dos_name[i+1] ='\0';
	}
	else	
	{	
		return 1;
	}	
	
	temp = strstr(toto,"subject");
	while(temp != NULL )
	{
		if(compteur == 0)
		{	
			temp = GetPolicy(dos_name, temp, compteur);
			compteur++;
		}
		else
		{
			temp = GetPolicy(dos_name, temp, compteur);
		}
		temp = strstr(temp,"subject");
		index_tableau++;
	}
	// ExFreePool(toto);
	// ExFreePool(buffer);
	return status;
}

char * GetPolicy(char * dos_name, char * temp, int compt)
{
	char * temporaire;
	char sujet[524];
	char object[524];
	char un[1];
	unsigned long hash_temp;
	char droit_temp[20];
	int i = 0, j=0, tour=0;
	Object * ptr;
	
	ptr = (Object * )ExAllocatePool(NonPagedPool, sizeof(Object));
	
	RtlZeroMemory(&un, 1);
	RtlZeroMemory(&droit_temp, 20);
	RtlZeroMemory(&sujet, 524);
	RtlZeroMemory(&object, 524);
	RtlZeroMemory(&ptr->droit, 20);
	
	if(compt != 0)
	{
		temporaire = strstr(temp, "\\");

		strncpy(sujet,dos_name, strlen(dos_name));
		j=strlen(sujet);
		if(temporaire != NULL)
		{
			while(temporaire[i] != '{')
			{
				sujet[j] = temporaire[i];
				i++;
				j++;
			}
			sujet[j-1]='\0';
		}
	}
	else
		sprintf(sujet,"System");
	
	hash_table[index_tableau] = hash_function(sujet);
	i = 0; j=0;
	// Parcours des objet et des droits associes
	temp = strstr(temp, "{" ) + 2; // Premier ligne de configuration
	un[0] = temp[0];
	un[1] = '\0';
		
	if(!strcmp(un,"}") )
		return "Error";
	
	while( strcmp(un, "}") )
	{
		if(tour == 0)
		{
			temporaire = strstr(temp, "\t")+1;
			while(temporaire[i] != '\n') i++;
			while(temporaire[i] != ' ')
			{
				i--;
				ptr->droit[j] = temporaire[i];
				j++;
			}
			ptr->droit[j-1]='\0';
			strncpy(object, temporaire,i-1);
			object[i-1] = '\0';
			ptr->name = hash_function(object);
			objet[index_tableau] = ptr;
			tour++;
			ptr->Next = NULL;
		}
		else
		{
			temporaire = strstr(temp, "\t")+1;
			while(temporaire[i] != '\n') i++;
			while(temporaire[i] != ' ')
			{
				i--;
				droit_temp[j] = temporaire[i];
				j++;
			}
			
			droit_temp[j-1]='\0';
			strncpy(object, temporaire,i-1);
			object[i-1] = '\0';
			hash_temp = hash_function(object);
			ptr = AddInStruct(hash_temp, droit_temp, ptr);
			ptr->Next=NULL;
		}
		
		i=0;j=0;
		temp = strstr(temp,"\n") +1;
		un[0] = temp[0];
		un[1] = '\0';
	}
	ptr = AddInStruct(0, "", ptr);
	// ExFreePool(ptr);
	return temp;
}

Object * AddInStruct(unsigned long hash, char * droit,  Object * structure)
{
	Object * struct_temp;
	struct_temp	=(Object * )ExAllocatePool(NonPagedPool, sizeof(Object));
	structure->Next = struct_temp;
	struct_temp->name = hash;
	RtlZeroMemory(&struct_temp->droit, 20);
	// strncpy(struct_temp->droit, droit, sizeof(droit)+1 );
	sprintf(struct_temp->droit, "%s", droit);
	struct_temp->Next =NULL;
	return struct_temp;
}

unsigned long  hash_function(char * str)
{
	unsigned long hash = 5312;
	int c;
	
	while(c = *str++)
		hash = ( (hash <<5) + hash) +c;
	
	return hash;
}

// Default
// 1 == pas authorise
// 0 == Ok
int SearchDatabase(char * name, char * droit, char * cible)
{
	int i=0, j=0, taille=0, compteur=0;
	unsigned long hash_cher, hash_cible;
	Object * parcours=NULL;
	
	hash_cher = hash_function(name);
	hash_cible = hash_function(cible);
	
	for(i=0;i<=index_tableau;i++)
	{
		if(hash_table[i] == hash_cher)
			break;
	}
	
	if(i > index_tableau)
		return 1;
	
	// DbgPrint("Dans Autorite\n");
	taille = strlen(droit);
	parcours = (Object * )objet[i];
	do
	{
		if(parcours == NULL)
			break;

		if(parcours->name == hash_cible)
		{

			for(i=0;i<=taille;i++)
			{
				j=0;
				while(parcours->droit[j])
				{	
					
					if(parcours->droit[j] == droit[i])
					{
						compteur++;
						break;
					}
					j++;
				}
			}
			// parcours = NULL;
			if(compteur == taille)
				return 0;
			else
				return 1;
		}
		 parcours = parcours->Next;
	}while(parcours->name != 0);
	
	parcours = NULL;
	return 1;
}
