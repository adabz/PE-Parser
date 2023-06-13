// pe-interface.c:
//    implements functions that deals with PE structures
//    read PE and save information in a struct
//

#include "headers.h"


// header section types
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

char section_flags_str[][34] = { "IMAGE_SCN_TYPE_NO_PAD",
"IMAGE_SCN_CNT_CODE", "IMAGE_SCN_CNT_INITIALIZED_DATA",
"IMAGE_SCN_CNT_UNINITIALIZED_ DATA", "IMAGE_SCN_LNK_OTHER",
"IMAGE_SCN_LNK_INFO", "IMAGE_SCN_LNK_REMOVE",
"IMAGE_SCN_LNK_COMDAT", "IMAGE_SCN_GPREL",
"IMAGE_SCN_MEM_PURGEABLE", "IMAGE_SCN_MEM_16BIT",
"IMAGE_SCN_MEM_LOCKED", "IMAGE_SCN_MEM_PRELOAD",
"IMAGE_SCN_ALIGN_1BYTES", "IMAGE_SCN_ALIGN_2BYTES",
"IMAGE_SCN_ALIGN_4BYTES", "IMAGE_SCN_ALIGN_8BYTES",
"IMAGE_SCN_ALIGN_16BYTES", "IMAGE_SCN_ALIGN_32BYTES",
"IMAGE_SCN_ALIGN_64BYTES", "IMAGE_SCN_ALIGN_128BYTES",
"IMAGE_SCN_ALIGN_256BYTES", "IMAGE_SCN_ALIGN_512BYTES",
"IMAGE_SCN_ALIGN_1024BYTES", "IMAGE_SCN_ALIGN_2048BYTES",
"IMAGE_SCN_ALIGN_4096BYTES", "IMAGE_SCN_ALIGN_8192BYTES",
"IMAGE_SCN_LNK_NRELOC_OVFL", "IMAGE_SCN_MEM_DISCARDABLE",
"IMAGE_SCN_MEM_NOT_CACHED", "IMAGE_SCN_MEM_NOT_PAGED",
"IMAGE_SCN_MEM_SHARED", "IMAGE_SCN_MEM_EXECUTE",
"IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_WRITE"};

uint32_t section_flags_arr[] = {0x00000008,
0x00000020, 0x00000040, 0x00000080, 0x00000100,
0x00000200, 0x00000800, 0x00001000, 0x00008000,
0x00020000, 0x00020000, 0x00040000, 0x00080000,
0x00100000, 0x00200000, 0x00300000, 0x00400000,
0x00500000, 0x00600000, 0x00700000, 0x00800000,
0x00900000, 0x00A00000, 0x00B00000, 0x00C00000,
0x00D00000, 0x00E00000, 0x01000000, 0x02000000,
0x04000000, 0x08000000, 0x10000000, 0x20000000,
0x40000000, 0x80000000};

// Image PE File type
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
char image_file_str[][35] = {"IMAGE_FILE_RELOCS_STRIPPED", "IMAGE_FILE_EXECUTABLE_IMAGE", 
                      "IMAGE_FILE_LINE_NUMS_STRIPPED", "IMAGE_FILE_LOCAL_SYMS_STRIPPED", 
                      "IMAGE_FILE_AGGRESSIVE_WS_TRIM", "IMAGE_FILE_LARGE_ADDRESS_AWARE", 
                      "IMAGE_FILE_BYTES_REVERSED_LO", "IMAGE_FILE_32BIT_MACHINE", 
                      "IMAGE_FILE_DEBUG_STRIPPED","IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 
                      "IMAGE_FILE_NET_RUN_FROM_SWAP", "IMAGE_FILE_SYSTEM", "IMAGE_FILE_DLL", 
                      "IMAGE_FILE_UP_SYSTEM_ONLY", "IMAGE_FILE_BYTES_REVERSED_HI"};

uint16_t image_file_arr[] = {0x0001, 0x0002, 0x0004,
                    0x0008, 0x0010, 0x0020, 0x0080, 0x0100,
                    0x0200, 0x0400, 0x0800, 0x1000, 0x2000,
                    0x4000, 0x8000};

// DLL Characteristics
char image_dll_str[][47] = {"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
                      "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                      "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
                      "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",		
                      "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
                      "IMAGE_DLLCHARACTERISTICS_NO_SEH",  		
                      "IMAGE_DLLCHARACTERISTICS_NO_BIND",
                      "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
                      "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
                      "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                      "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"};

uint16_t image_dll_arr[] = {0x0020, 0x0040, 0x0080, 0x0100,
0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000};


//-------------------------------------------
// A reminder
// A byte is       8 bits, 
// a word is       2 bytes (16 bits), 
// a doubleword is 4 bytes (32 bits), 
// a quadword is   8 bytes (64 bits).
//-------------------------------------------



// cleanup(): a function to clean allocated memory inside structs
// arguments: a pointer to Dos header object
// returns: none
void cleanup(dos_header_t *dosHeader)
{
  free(dosHeader->dataDirectory);
  for(int i = 0; i < dosHeader->pe.numberOfSections; i++)
  {
    free(dosHeader->section_table[i].name);
  }
  free(dosHeader->exportDir.exportAddr_name_t);
  free(dosHeader->section_table);
  free(dosHeader->importDir);
}

// rva_to_offset(): converts an RVA address to a file offset.
// arguments: the number of sections, rva and pointer to sections
// returns: converted file offset, or 0 if rva is 0, or -1 if it fails.
uint64_t rva_to_offset(int numberOfSections, uint64_t rva, 
                           section_table_t *sections)
{
  if(rva == 0) return 0;
  uint64_t sumAddr;

  for(int idx = 0; idx < numberOfSections; idx++) 
  {
    sumAddr = sections[idx].virtualAddr + sections[idx].sizeOfRawData;
    
    if( rva >= sections[idx].virtualAddr && (rva <= sumAddr) )
    {
      return  sections[idx].ptrToRawData + (rva - sections[idx].virtualAddr);
    }
  }
  return -1;
}

// print_pe_characteristics(): takes in a flags characteristics and prints them
// arguments: a WORD sized integer
// returns: none
void print_pe_characteristics(uint16_t ch)
{
  for(int idx = 0; idx < 15; idx++)
  {
    if( ch & (image_file_arr[idx]) )
     printf("     %s\n", image_file_str[idx]);
  }
}

// print_dllcharacteristics(): takes in a flags characteristics and prints them
// arguments: a WORD sized integer
// returns: none
void print_dllcharacteristics(uint16_t ch)
{
  for(int idx = 0; idx < 11; idx++)
  {
    if( ch & (image_dll_arr[idx]) )
      printf("     %s\n", image_dll_str[idx]);
  }
}

// print_magic(): prints the type of a PE image
// arguments: a WORD sized integer
// returns: none
void print_magic(uint16_t magic)
{
  switch (magic)
  {
  case OPTIONAL_IMAGE_PE32:
    printf("%X (PE) \n", OPTIONAL_IMAGE_PE32);
    break;

  case OPTIONAL_IMAGE_PE32_plus:
    printf("%X (PE+) \n", OPTIONAL_IMAGE_PE32_plus);
    break;

  default:
    printf("0 (Error) \n");
    break;
  }
}

// print_machine(): prints the machine type of a PE image
// arguments: a WORD sized integer
// returns: none
void print_machine(uint16_t mach)
{
  switch (mach)
  {
  case IMAGE_FILE_MACHINE_UNKNOWN:
    printf("(%X)  IMAGE_FILE_MACHINE_UNKNOWN\n", IMAGE_FILE_MACHINE_UNKNOWN);
    break;

  case IMAGE_FILE_MACHINE_IA64:
    printf("(%X)  IMAGE_FILE_MACHINE_IA64\n", IMAGE_FILE_MACHINE_IA64);
    break;

  case IMAGE_FILE_MACHINE_I386:
    printf("(%X)  IMAGE_FILE_MACHINE_I386\n", IMAGE_FILE_MACHINE_I386);
    break;

  case IMAGE_FILE_MACHINE_AMD64:
    printf("(%X)  IMAGE_FILE_MACHINE_AMD64\n", IMAGE_FILE_MACHINE_AMD64);
    break;

  case IMAGE_FILE_MACHINE_ARM:
    printf("(%X)  IMAGE_FILE_MACHINE_ARM\n", IMAGE_FILE_MACHINE_ARM);
    break;

  case IMAGE_FILE_MACHINE_ARM64:
    printf("(%X)  IMAGE_FILE_MACHINE_ARM64\n", IMAGE_FILE_MACHINE_ARM64);
    break;

  case IMAGE_FILE_MACHINE_ARMNT:
    printf("(%X)  IMAGE_FILE_MACHINE_ARMNT\n", IMAGE_FILE_MACHINE_ARM64);
    break;

  case IMAGE_FILE_MACHINE_EBC:
    printf("(%X)  IMAGE_FILE_MACHINE_EBC\n", IMAGE_FILE_MACHINE_EBC);
    break;

  default:
    break;
  }
}

// print_subsystem(): prints the subsystem of a PE
// arguments: a WORD sized integer
// returns: none
void print_subsystem(uint16_t system){
  switch (system)
  {
  case IMAGE_SUBSYSTEM_UNKNOWN:
    printf("  (%X)   IMAGE_SUBSYSTEM_UNKNOWN\n", IMAGE_SUBSYSTEM_UNKNOWN);
    break;

  case IMAGE_SUBSYSTEM_NATIVE:
    printf("  (%X)   IMAGE_SUBSYSTEM_NATIVE\n", IMAGE_SUBSYSTEM_NATIVE);
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_GUI:
    printf("  (%X)   IMAGE_SUBSYSTEM_WINDOWS_GUI\n", IMAGE_SUBSYSTEM_WINDOWS_GUI);
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_CUI:
    printf("  (%X)   IMAGE_SUBSYSTEM_WINDOWS_CUI\n", IMAGE_SUBSYSTEM_WINDOWS_CUI);
    break;

  case IMAGE_SUBSYSTEM_OS2_CUI:
    printf("     IMAGE_SUBSYSTEM_OS2_CUI\n");
    break;

  case IMAGE_SUBSYSTEM_POSIX_CUI:
    printf("     IMAGE_SUBSYSTEM_POSIX_CUI\n");
    break;

  case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
    printf("     IMAGE_SUBSYSTEM_NATIVE_WINDOWS\n");
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
    printf("     IMAGE_SUBSYSTEM_WINDOWS_CE_GUI\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_APPLICATION:
    printf("     IMAGE_SUBSYSTEM_EFI_APPLICATION\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
    printf("     IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
    printf("     IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_ROM:
    printf("     IMAGE_SUBSYSTEM_EFI_ROM\n");
    break;

  case IMAGE_SUBSYSTEM_XBOX:
    printf("     IMAGE_SUBSYSTEM_XBOX\n");
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
    printf("     IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION\n");
    break;

  default:
    break;
  }
}

// print_section_characteristics(): prints the flags set on a section
// arguments: a DWORD sized integer
// returns: none
void print_section_characteristics(uint32_t ch){
  for(int i = 0; i < 35; i++)
  {
    if( ch & (section_flags_arr[i]) )
    {
      printf("          %s\n", section_flags_str[i]);
    }
  }
}


// read_dos(): reads DOS Header values from a file
// arguments: a FILE stream object, a pointer to a Dos header struct
// returns: none
void read_dos(FILE *in, dos_header_t *dosHeader)
{
  // Reading DOS Header
  dosHeader->magic      = read16_le(in);
  dosHeader->e_cblp     = read16_le(in);
  dosHeader->e_cp       = read16_le(in);
  dosHeader->e_crlc     = read16_le(in);
  dosHeader->e_cparhdr  = read16_le(in);
  dosHeader->e_minalloc = read16_le(in);
  dosHeader->e_maxalloc = read16_le(in);
  dosHeader->e_ss       = read16_le(in);
  dosHeader->e_sp       = read16_le(in);
  dosHeader->e_csum     = read16_le(in);
  dosHeader->e_ip       = read16_le(in);
  dosHeader->e_cs       = read16_le(in);
  dosHeader->e_lfarlc   = read16_le(in);
  dosHeader->e_ovno     = read16_le(in);

  // some of the next fields are reserved/aren't used
  dosHeader->e_res      = read64_le(in);
  dosHeader->e_oemid    = read16_le(in);
  dosHeader->e_oeminfo  = read16_le(in);
  dosHeader->e_res2     = read64_le(in); // this is repeated on purpose since
  dosHeader->e_res2     = read64_le(in); // most PE files have this field as zero
  dosHeader->e_res2     = read32_le(in); // i'll fix it later.
  /////////////////////////////////////////////
  dosHeader->e_lfanew   = read32_le(in);
}


// read_pe(): reads in PE header information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_pe(FILE *in, dos_header_t *dosHeader)
{

  if( fseek(in, dosHeader->e_lfanew, SEEK_SET) == -1 )
  {  
    printf("Error during file reading.\n");
    exit(-1);
  } 

  // PE header
  dosHeader->pe.signature          = read32_le(in);
  dosHeader->pe.machine            = read16_le(in);
  dosHeader->pe.numberOfSections   = read16_le(in);
  dosHeader->pe.timeStamp          = read32_le(in);
  dosHeader->pe.symTablePtr        = read32_le(in);
  dosHeader->pe.numberOfSym        = read32_le(in);
  dosHeader->pe.optionalHeaderSize = read16_le(in);
  dosHeader->pe.characteristics    = read16_le(in);
  
  // optional header (Standard Fields)
  dosHeader->pe.optionalHeader.magic          = read16_le(in);
  dosHeader->pe.optionalHeader.majorLinkerVer = read8_le(in);
  dosHeader->pe.optionalHeader.minorLinkerVer = read8_le(in);
  dosHeader->pe.optionalHeader.sizeOfCode     = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfInitializedData    = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfUninitializedData  = read32_le(in);
  dosHeader->pe.optionalHeader.entryPoint = read32_le(in);
  dosHeader->pe.optionalHeader.baseOfCode = read32_le(in);
  if( dosHeader->pe.optionalHeader.magic == OPTIONAL_IMAGE_PE32_plus )
  {
    dosHeader->pe.optionalHeader.imageBase        = read64_le(in);
  } else {
    dosHeader->pe.optionalHeader.baseOfData       = read32_le(in);
    dosHeader->pe.optionalHeader.imageBase        = read32_le(in);
  }
  
  dosHeader->pe.optionalHeader.sectionAlignment  = read32_le(in);
  dosHeader->pe.optionalHeader.fileAlignment     = read32_le(in);
  dosHeader->pe.optionalHeader.majorOSVer        = read16_le(in);
  dosHeader->pe.optionalHeader.minorOSVer        = read16_le(in);
  dosHeader->pe.optionalHeader.majorImageVer     = read16_le(in);
  dosHeader->pe.optionalHeader.minorImageVer     = read16_le(in);
  dosHeader->pe.optionalHeader.majorSubsystemVer = read16_le(in);
  dosHeader->pe.optionalHeader.minorSubsystemVer = read16_le(in);
  dosHeader->pe.optionalHeader.win32VersionVal   = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfImage       = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfHeaders     = read32_le(in);
  dosHeader->pe.optionalHeader.checkSum          = read32_le(in);
  dosHeader->pe.optionalHeader.subsystem         = read16_le(in);
  dosHeader->pe.optionalHeader.dllCharacteristics= read16_le(in);
  
  if( dosHeader->pe.optionalHeader.magic == OPTIONAL_IMAGE_PE32_plus )
  {
    dosHeader->pe.optionalHeader.sizeOfStackReserve= read64_le(in);
    dosHeader->pe.optionalHeader.sizeOfStackCommit = read64_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapReserve = read64_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapCommit  = read64_le(in);      
  } else {
    dosHeader->pe.optionalHeader.sizeOfStackReserve= read32_le(in);
    dosHeader->pe.optionalHeader.sizeOfStackCommit = read32_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapReserve = read32_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapCommit  = read32_le(in);
  }
  dosHeader->pe.optionalHeader.loaderFlags         = read32_le(in);
  dosHeader->pe.optionalHeader.numberOfRvaAndSizes = read32_le(in);
}

// read_dataDir(): reads in Data Directories information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_dataDir(FILE *in, dos_header_t *dosHeader)
{
  int dirs = dosHeader->pe.optionalHeader.numberOfRvaAndSizes;

  // Reading Data Directories
  dosHeader->dataDirectory = malloc(sizeof(data_directory_t) * dirs );

  for(int idx = 0; idx < dirs ; idx++)
  {
    dosHeader->dataDirectory[idx].virtualAddr = read32_le(in);
    dosHeader->dataDirectory[idx].size = read32_le(in);
    // dosHeader->dataDirectory[idx].offset = rva_to_offset(dosHeader->pe.numberOfSections,
    //                               dosHeader->dataDirectory[idx].virtualAddr,
    //                               dosHeader->section_table);
  }
}

void read_dataOffset(dos_header_t *dosHeader){
  int dirs = dosHeader->pe.optionalHeader.numberOfRvaAndSizes;

  for(int idx = 0; idx < dirs ; idx++)
  {
    dosHeader->dataDirectory[idx].offset = rva_to_offset(dosHeader->pe.numberOfSections,
                                  dosHeader->dataDirectory[idx].virtualAddr,
                                  dosHeader->section_table);
  }
}

// read_sections(): reads in sections information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_sections(FILE *in, dos_header_t *dosHeader)
{
  int sections = dosHeader->pe.numberOfSections;
  // Reading Sections data
  dosHeader->section_table = malloc(sizeof(section_table_t) * sections  );

  for(int idx = 0; idx < sections; idx++)
  {
    dosHeader->section_table[idx].name            = read_str(in, 8);
    dosHeader->section_table[idx].virtualSize     = read32_le(in);
    dosHeader->section_table[idx].virtualAddr     = read32_le(in);
    dosHeader->section_table[idx].sizeOfRawData   = read32_le(in);
    dosHeader->section_table[idx].ptrToRawData    = read32_le(in);
    dosHeader->section_table[idx].ptrToReloc      = read32_le(in);
    dosHeader->section_table[idx].ptrToLineNum    = read32_le(in);
    dosHeader->section_table[idx].numberOfReloc   = read16_le(in);
    dosHeader->section_table[idx].numberOfLineNum = read16_le(in);
    dosHeader->section_table[idx].characteristics = read32_le(in);
  }

}

// read_exportDir(): reads in Export directory information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_exportDir(FILE *in, dos_header_t *dosHeader)
{
  uint32_t offset;
  
  offset = dosHeader->dataDirectory[0].offset;
  
  if( offset < 0 ) return;

  if( fseek(in, offset, SEEK_SET) == -1 )
  {
    printf("fseek failed in read exports.\n");
    return;
  }
  
  dosHeader->exportDir.exportFlags  = read32_le(in);
  dosHeader->exportDir.timeStamp    = read32_le(in);
  dosHeader->exportDir.majorVer     = read16_le(in);
  dosHeader->exportDir.minorVer     = read16_le(in);
  dosHeader->exportDir.nameRVA      = read32_le(in);
  dosHeader->exportDir.ordinalBase          = read32_le(in);
  dosHeader->exportDir.addrTableEntries     = read32_le(in);
  dosHeader->exportDir.numberOfNamePointers = read32_le(in);
  dosHeader->exportDir.exportAddrTableRVA   = read32_le(in);
  dosHeader->exportDir.namePtrRVA           = read32_le(in);
  dosHeader->exportDir.ordinalTableRVA      = read32_le(in);

  read_exportNames(in, dosHeader);
}


// read_exportNames(): reads the ascii names of exported functions
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_exportNames(FILE *in, dos_header_t *dosHeader)
{
  uint32_t tableOffset;
  uint32_t nameOffset;
  uint32_t nameRVA;
  uint32_t tableSize;
  char buffer[100];

  tableSize = dosHeader->exportDir.numberOfNamePointers;
  tableOffset = rva_to_offset(dosHeader->pe.numberOfSections,
                             dosHeader->exportDir.namePtrRVA, 
                             dosHeader->section_table);
  dosHeader->exportDir.exportAddr_name_t = malloc(
                                    sizeof(export_address_name_t) * tableSize);


  // reading Import table entries (per DLL)
  for(uint32_t idx = 0; idx < tableSize; idx++)
  { 
    fseek(in, tableOffset, 0);
    nameRVA = read32_le(in);
    nameOffset = rva_to_offset(dosHeader->pe.numberOfSections,
          nameRVA, dosHeader->section_table);
    fseek(in, nameOffset, 0);
    fgets(buffer, 100, in);
    //printf("Got export: %s\n", buffer);
    strcat(dosHeader->exportDir.exportAddr_name_t[idx].names, buffer);

    tableOffset += 4; // after reading 4 bytes, jump to next 4 bytes
  }
}


// read_importDir(): reads the imports table entries
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_importDir(FILE *in, dos_header_t *dosHeader)
{
  uint32_t tableEntries;

  // each import entry has 5 fields, 4 bytes per field (20 bytes per entry)
  // minus 1 because the final table will be empty signaling the end of entries
  tableEntries = (dosHeader->dataDirectory[1].size / 20) - 1 ;
  fseek(in, dosHeader->dataDirectory[1].offset, 0);

  dosHeader->importDir = malloc(sizeof(import_directory_t) * tableEntries);

  for(uint32_t idx = 0; idx < tableEntries; idx++)
  {
    dosHeader->importDir[idx].importLookupTableRVA = read32_le(in);
    dosHeader->importDir[idx].timeStamp        = read32_le(in);
    dosHeader->importDir[idx].forwarderChain   = read32_le(in);
    dosHeader->importDir[idx].nameRVA          = read32_le(in);
    dosHeader->importDir[idx].importAddressRVA = read32_le(in);
  }

}

/*  PE specific functions
  After having read the entire PE file, the functions here can be used
  to read or re·trieve specific values form the PE file, such as:
  - get_ImageBase(): to get the hex value of the image base
  - get_sectionsCount(): to get the number of sections in a PE
  - get_peOffset(): to get the offset of the PE header in the file
  - ...etc
*/

