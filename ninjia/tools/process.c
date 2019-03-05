#include "../loader/loader.h"


unsigned int FindProcessId(const char *processname)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    unsigned int result = NULL;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);
	printf("[+] CreateToolhelp32Snapshot success\n");

    pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        printf("!!! Failed to gather information on system processes! \n");
        return 0;
    }

    do
    {
        //printf("Checking process %ls\n", pe32.szExeFile);
		char pidName[MAX_PATH] = "";
		printf("pid:%ld,name:", pe32.th32ProcessID);
		for (int i = 0; i < MAX_PATH; i++) {
			if (pe32.szExeFile[i] == '\0' || pe32.szExeFile[i] == '.') break;
			pidName[i] = pe32.szExeFile[i];
			printf("%c", pidName[i]);
		}
		printf("\n");
        if (0 == strcmp(processname, pidName))
        {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return result;
}