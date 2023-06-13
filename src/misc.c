// misc.c:
//    misc functions used in most of the code that are not 
//    specific to PE parsing, but can be used anywhere else.
//

#include "headers.h"

// read_str(): reads a 'count' of characters from a file
// arguments: FILE stream to read from, count of characters to read
// returns: pointer to a string of characters.
char *read_str(FILE *in, int count)
{
  char *ch_ptr = malloc(sizeof(char)*count);
  for(int i = 0; i < count; i++)
  {
    ch_ptr[i] = fgetc(in);
  }
  ch_ptr[strlen(ch_ptr)] = 0;
  return ch_ptr;
}

// read8_le(): reads an 8bit integer
// arguments: a file stream to read from
// return: an 8 bit integer
uint8_t  read8_le(FILE *in)
{
  return fgetc(in);
}

// read16_le(): reads an 16bit little-endian integer
// arguments: a file stream to read from
// return: an 16 bit integer
uint16_t  read16_le(FILE *in)
{
  uint16_t value;
  value = fgetc(in);
  value |= (fgetc(in)<<8);
  return value;
}

// read32_le(): reads an 32bit little-endian integer
// arguments: a file stream to read from
// return: an 32 bit integer
uint32_t  read32_le(FILE *in)
{
  uint32_t value;
  value = fgetc(in);
  value |= (fgetc(in)<<8);
  value |= (fgetc(in)<<16);
  value |= (fgetc(in)<<24);
  return value;
}

// read64_le(): reads an 64bit little-endian integer
// arguments: a file stream to read from
// return: an 64 bit integer
uint64_t  read64_le(FILE *in)
{
  uint64_t value;
  value = (uint64_t)fgetc(in);
  value |= ((uint64_t)fgetc(in) <<8);
  value |= ((uint64_t)fgetc(in) <<16);
  value |= ((uint64_t)fgetc(in) <<24);
  value |= ((uint64_t)fgetc(in) <<32);
  value |= ((uint64_t)fgetc(in) <<40);
  value |= ((uint64_t)fgetc(in) <<48);
  value |= ((uint64_t)fgetc(in) <<54);

  return value;
}

// print_sections(): prints PE sections info
// arguments: a pointer to dosheader object
// return: none
void print_sections(dos_header_t *dosHeader)
{
  section_table_t *sections;
  sections = dosHeader->section_table;
  printf("\nSections: \n");

  for(int idx = 0; idx < dosHeader->pe.numberOfSections ;idx++ )
  {
      printf("   Name: %s\n", sections[idx].name );
      printf("       VirtualAddress:        %X\n", sections[idx].virtualAddr );
      printf("       VirtualSize:           %X\n", sections[idx].virtualSize );
      printf("       SizeOfRawData:         %X\n", sections[idx].sizeOfRawData );
      printf("       PointerToRawData:      %X\n", sections[idx].ptrToRawData );
      printf("       PointerToRelactons:    %X\n", sections[idx].ptrToReloc );
      printf("       PointerToLinenumbers:  %X\n", sections[idx].ptrToLineNum );
      printf("       NumberOfRelocations:   %X\n", sections[idx].numberOfReloc );
      printf("       NumberOfLinenumbers:   %X\n", sections[idx].numberOfLineNum );
      printf("       Characteristics:       %X\n", sections[idx].characteristics );
      print_section_characteristics(sections[idx].characteristics);
  }
}

// load_file(): loads and reads PE files in current directory
// arguments: integer represneting argument count, and a pointer 
// to an argument array containing at least 1 valid argument.
// return: none
void load_file(int argc, char *argv[])
{
  dos_header_t dosHeader;
  FILE *in;

  for(int idx = 1; idx < argc; idx++)
  {
    in = fopen(argv[idx], "rb");
    if( in == NULL )
    {
      printf("Can't open '%s' file, exiting\n", argv[idx]);
      continue;
    }      

    // read headers
    read_dos(in, &dosHeader);    
    read_pe(in, &dosHeader);

    // making sure we have a valid/standard PE file
    if( dosHeader.pe.signature != 0x4550 )
    {
        printf("invalid PE signature, file is likely corrupt PE, or not a valid PE file.\n");
        fclose(in);
        return;
    }

    read_dataDir(in, &dosHeader);
    read_sections(in, &dosHeader);
    read_dataOffset(&dosHeader);
    read_exportDir(in, &dosHeader);
    read_importDir(in, &dosHeader);
    

    // test printing information
    printf("showing file: %s \n\n", argv[idx]);

    print_headers(&dosHeader);
    print_dataTables(&dosHeader);
    print_sections(&dosHeader);
    print_exports(&dosHeader);
    print_imports(&dosHeader);

    // cleanup
    cleanup(&dosHeader);
    fclose(in);
  }
}

// print_headers(): prints the values of a DOS header object
// arguments: a pointer to a dosheader object
// return: none
void print_headers(dos_header_t *dosHeader)
{

  printf("Magic bytes: \t\t%c%c\n", (0xff & dosHeader->magic), 
                                    (dosHeader->magic>>8) );
  printf("PE Offset    \t\t%X\n", dosHeader->e_lfanew);

  printf("\nPE header information\n");
  printf(" Signature:   \t\t0x%X (%c%c) \n",  dosHeader->pe.signature, 
                                     (0xff & dosHeader->pe.signature), 
                                     0xff & (dosHeader->pe.signature>>8) );

  printf(" Machine:  \t\t");
  print_machine(dosHeader->pe.machine);

  printf(" Sections: \t\t%d\n", dosHeader->pe.numberOfSections);
  printf(" Time Stamp: \t\t0x%X\n", dosHeader->pe.timeStamp);
  printf(" Symbol Table Pointer:  0x%X\n", dosHeader->pe.symTablePtr);
  printf(" Symbols:               %d\n", dosHeader->pe.numberOfSym);
  printf(" OpionalHeader Size:    %d (0x%X)\n", dosHeader->pe.optionalHeaderSize, 
                                                dosHeader->pe.optionalHeaderSize);
  printf(" Characteristics:       0x%X\n", dosHeader->pe.characteristics);
  print_pe_characteristics(dosHeader->pe.characteristics);
  
  printf("\nOptional Header\n");
  printf("Magic:      ");
  print_magic(dosHeader->pe.optionalHeader.magic);
  printf("MajorLinkerVersion:      0x%X\n", dosHeader->pe.optionalHeader.majorLinkerVer);
  printf("MinorLinkerVersion:      0x%X\n", dosHeader->pe.optionalHeader.minorLinkerVer);
  printf("SizeOfCode:              0x%X\n", dosHeader->pe.optionalHeader.sizeOfCode);
  printf("SizeOfInitializedData:   0x%X\n", dosHeader->pe.optionalHeader.sizeOfInitializedData);
  printf("SizeOfUninitializedData: 0x%X\n", dosHeader->pe.optionalHeader.sizeOfUninitializedData);
  printf("EntryPoint:              0x%X\n", dosHeader->pe.optionalHeader.entryPoint);
  printf("BaseOfCode:              0x%X\n", dosHeader->pe.optionalHeader.baseOfCode);
  if( dosHeader->pe.optionalHeader.magic == OPTIONAL_IMAGE_PE32 ){
    printf("BaseOfData:              0x%X\n", dosHeader->pe.optionalHeader.baseOfData);
  }
  printf("ImageBase:               %p\n", (void*) dosHeader->pe.optionalHeader.imageBase);
  printf("SectionAlignment:        0x%X\n", dosHeader->pe.optionalHeader.sectionAlignment);
  printf("FileAlignment:           0x%X\n", dosHeader->pe.optionalHeader.fileAlignment);
  printf("MajorOSVersion:          0x%X\n", dosHeader->pe.optionalHeader.majorOSVer);
  printf("MinorOSVersion:          0x%X\n", dosHeader->pe.optionalHeader.minorOSVer);  
  printf("MajorImageVersion:       0x%X\n", dosHeader->pe.optionalHeader.majorImageVer);
  printf("MinorImageVersion:       0x%X\n", dosHeader->pe.optionalHeader.minorImageVer);
  printf("MajorSubsysVersion:      0x%X\n", dosHeader->pe.optionalHeader.majorSubsystemVer);
  printf("MinorSubsysVersion:      0x%X\n", dosHeader->pe.optionalHeader.minorSubsystemVer);
  printf("Win32VersionValue:       0x%X\n", dosHeader->pe.optionalHeader.win32VersionVal);
  printf("SizeOfImage:             0x%X\n", dosHeader->pe.optionalHeader.sizeOfImage);
  printf("SizeOfHeaders:           0x%X\n", dosHeader->pe.optionalHeader.sizeOfHeaders);
  printf("CheckSum:                0x%X\n", dosHeader->pe.optionalHeader.checkSum);
  printf("Subsystem:             ");
  print_subsystem(dosHeader->pe.optionalHeader.subsystem);
  printf("DllCharacteristics:           \n");
  print_dllcharacteristics(dosHeader->pe.optionalHeader.dllCharacteristics);

  printf("SizeOfStackReserve:      %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfStackReserve);
  printf("SizeOfStackCommit:       %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfStackCommit);
  printf("SizeOfHeapReserve:       %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfHeapReserve);
  printf("SizeOfHeapCommit:        %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfHeapCommit);

  printf("LoaderFlags:             0x%X\n", dosHeader->pe.optionalHeader.loaderFlags);
  printf("NumberOfRvaAndSizes:     %d\n", dosHeader->pe.optionalHeader.numberOfRvaAndSizes);

}

// print_dataTables(): prints a list of data tables in a PE file
// arguments: a pointer to a dosheader object
// return: none
void print_dataTables(dos_header_t *dosHeader)
{
  // Data Directories Types
  char dataTable[][25] = { "Export Table",       "Import Table",
                         "Resource Table",    "Exception Table",
                           "Certificate ",    "Base Relocation",
                            "Debug Table",       "Architecture",
                       "Global Ptr Table",          "TLS Table",
                           "Load Config ",       "Bound Import",
                         "Import Address", "Delay Import Desc.",
                     "CLR Runtime Header", "Reserved, must be zero"};

  uint32_t offset, vAddress, sections, tables;
  sections = dosHeader->pe.numberOfSections;

  tables = dosHeader->pe.optionalHeader.numberOfRvaAndSizes;

  printf("\nData Tables: \n");
  for(int idx = 0; idx < tables; idx++)
  {
      vAddress = dosHeader->dataDirectory[idx].virtualAddr;

      // skipping empty directories
      if( vAddress == 0 ) continue;

      printf("  %s: \n", dataTable[idx]);

      offset = rva_to_offset(sections, vAddress, dosHeader->section_table);

      printf("     Address: 0x%X \tOffset: %X\n", vAddress, offset);
      printf("        Size: 0x%X \n", dosHeader->dataDirectory[idx].size);
  }
}

// print_exports(): prints a list of exports in a PE file
// arguments: a pointer to a dosheader object
// return: none
void print_exports(dos_header_t *dosHeader)
{
  printf("\nExport Directory \n");
  printf("    Flags:           0x%X\n", dosHeader->exportDir.exportFlags);
  printf("    TimeStamp:       0x%X\n", dosHeader->exportDir.timeStamp);
  printf("    MajorVersion:    0x%X\n", dosHeader->exportDir.majorVer);
  printf("    MinorVersion:    0x%X\n", dosHeader->exportDir.minorVer);
  printf("    Name RVA:        0x%X\n", dosHeader->exportDir.nameRVA);
  printf("    OrdinalBase:     0x%X\n", dosHeader->exportDir.ordinalBase);
  printf("    AddressTable Entries:  0x%X\n", dosHeader->exportDir.addrTableEntries);
  printf("    NumberOfNames:         0x%X\n", dosHeader->exportDir.numberOfNamePointers);
  printf("    ExportTable Entries:   0x%X\n", dosHeader->exportDir.exportAddrTableRVA);
  printf("    AddressOfNames:        0x%X\n", dosHeader->exportDir.namePtrRVA);
  printf("    OrdinalTable RVA:      0x%X\n", dosHeader->exportDir.ordinalTableRVA);

  printf("\nExported functions: \n");
  
  // skipping none IMAGE_FILE_DLL
  if( (dosHeader->pe.characteristics & 0x2000) == 0 ) return;

  for(int i = 0; i < dosHeader->exportDir.numberOfNamePointers; i++){
    printf("   %s\n", dosHeader->exportDir.exportAddr_name_t[i].names);
  }
  
}

// print_exports(): prints a list of exports in a PE file
// arguments: a pointer to a dosheader object
// return: none
void print_imports(dos_header_t *dosHeader)
{
  uint32_t tableEntries;

  tableEntries = (dosHeader->dataDirectory[1].size / 20) - 1 ;
  printf("\nExport Directory \n");

  for(uint32_t idx = 0; idx < tableEntries; idx++)
  {
    printf("  Import Lookup table RVA: %x\n", dosHeader->importDir[idx].importLookupTableRVA);
    printf("  Time Stamp:              %x\n", dosHeader->importDir[idx].timeStamp);
    printf("  Forwarder Chain:         %x\n", dosHeader->importDir[idx].forwarderChain);
    printf("  Name RVA:                %x\n", dosHeader->importDir[idx].nameRVA);
    printf("  Import Address table RVA: %x\n\n", dosHeader->importDir[idx].importAddressRVA);
  }

}