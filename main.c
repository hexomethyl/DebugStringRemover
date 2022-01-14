#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

//Thanks, Jon for function
uint8_t* rva_to_pointer(uint8_t* image, PIMAGE_SECTION_HEADER section_header, size_t section_count, uint32_t rva)
{
    for (size_t i = 0; i < section_count; ++i) {
        IMAGE_SECTION_HEADER section = section_header[i];

        if (rva >= section.VirtualAddress && rva <= section.VirtualAddress + section.SizeOfRawData) {
            return image + section.PointerToRawData + rva - section.VirtualAddress;
        }
    }

    return NULL;
}

int main(int argc, char** argv)
{
    if (argc < 2) // no arguments were passed
    {
        printf("Usage: DebugStringRemover.exe PE_FILE");
        exit(-1);
    }

    //Open file with RW perms
    HANDLE dllHandle = CreateFileA(argv[1], GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (dllHandle == INVALID_HANDLE_VALUE)
    {
        printf("Could not read file");
        exit(-1);
    } 

    // allocate heap
    uint64_t fileSize = GetFileSize(dllHandle, NULL);
    BYTE* fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    DWORD bytesRead = 0;
    // read file bytes to memory
    ReadFile(dllHandle, fileData, fileSize, &bytesRead, NULL);
    if(bytesRead != fileSize)
    {
        printf("File read incorrectly");
        exit(-1);
    }

    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)fileData;
    IMAGE_NT_HEADERS64* NT_HEADER64 = (IMAGE_NT_HEADERS*)(fileData + (DOS_HEADER->e_lfanew));
    IMAGE_OPTIONAL_HEADER* OPTIONAL_HEADER = (IMAGE_OPTIONAL_HEADER*) &(NT_HEADER64->OptionalHeader);
    IMAGE_DATA_DIRECTORY* DEBUG_DIRECTORY_INFO = &(OPTIONAL_HEADER->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]);
    PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(NT_HEADER64);

    IMAGE_DEBUG_DIRECTORY* DEBUG_DIRECTORY = (PIMAGE_DEBUG_DIRECTORY) rva_to_pointer(
            fileData,
            firstSection,
            NT_HEADER64->FileHeader.NumberOfSections,
            DEBUG_DIRECTORY_INFO->VirtualAddress
    );

    if(!DEBUG_DIRECTORY)
    {
        printf("PE file does not contain debug directory");
        exit(-1);
    }

    if(!memcmp(DEBUG_DIRECTORY,"RSDS",4))
    {
        printf("PE file does not contain debug directory");
        exit(-1);
    }

    printf_s("PDB String:\n%s",fileData + DEBUG_DIRECTORY->PointerToRawData+24,DEBUG_DIRECTORY->SizeOfData-24);
    memset(fileData + DEBUG_DIRECTORY->PointerToRawData, 0, DEBUG_DIRECTORY->SizeOfData);
    memset(DEBUG_DIRECTORY, 0, DEBUG_DIRECTORY_INFO->Size);
    DEBUG_DIRECTORY_INFO->VirtualAddress = 0;
    DEBUG_DIRECTORY_INFO->Size = 0;

    SetFilePointer(dllHandle, 0, NULL, FILE_BEGIN);
    if(!WriteFile(dllHandle,fileData,fileSize,&bytesRead,NULL))
    {
        printf("Error writing to file");
        exit(-1);
    }
    HeapFree(GetProcessHeap(),0,fileData);
    CloseHandle(dllHandle);

    
    return 0;
}
