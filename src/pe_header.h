// pe_header.h
//    Definitions and declarations for PE module
//
#ifndef PE_HEADER_H
#define PE_HEADER_H

// Disable warning for fopen() under visual studio
#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

#include "headers.h"

// Import Table
typedef struct import_directory_t{
  uint32_t importLookupTableRVA;// RVA of the import lookup table 
  uint32_t timeStamp;       
  uint32_t forwarderChain; 
  uint32_t nameRVA;             // address of an ASCII string name of the DLL
  uint32_t importAddressRVA;
}import_directory_t;

// export address table
typedef struct export_address_name_t{
  char   names[1024];
}export_address_name_t;

// export table
typedef struct export_directory_t{
  uint32_t    exportFlags;      // Reserved, must be 0. 
  uint32_t    timeStamp;        // The time and date that the export 
                                // data was created. 

  uint16_t    majorVer;
  uint16_t    minorVer;
  uint32_t    nameRVA;          // The address of the ASCII string that contains
                                // the name of the DLL.

  uint32_t    ordinalBase;          // The starting ordinal number for exports in 
                                // this image. This field specifies the 
                                // starting ordinal number for the export 
                                // address table. 

  uint32_t    addrTableEntries;     // The number of entries in the 
                                    // export address table. 
  uint32_t    numberOfNamePointers;
  uint32_t    exportAddrTableRVA; // The address of the export address table,
  uint32_t    namePtrRVA;
  uint32_t    ordinalTableRVA;
  export_address_name_t *exportAddr_name_t;
}export_directory_t;

// section table
typedef struct section_table_t{
  char       *name;
  uint32_t    virtualSize;
  uint32_t    virtualAddr;
  uint32_t    sizeOfRawData;
  uint32_t    ptrToRawData;
  uint32_t    ptrToReloc;
  uint32_t    ptrToLineNum;
  uint32_t    numberOfReloc;
  uint32_t    numberOfLineNum;
  uint32_t    characteristics;
}section_table_t;

// Data Directory 
typedef struct data_directory_t{
  uint64_t    offset;
  uint32_t    virtualAddr; 
  uint32_t    size;
}data_directory_t;

// Optional Header Image
typedef struct optional_header_t{
  uint16_t    magic;  
  uint8_t     majorLinkerVer;
  uint8_t     minorLinkerVer;
  uint32_t    sizeOfCode;
  uint32_t    sizeOfInitializedData;
  uint32_t    sizeOfUninitializedData;
  uint32_t    entryPoint;
  uint32_t    baseOfCode;
  uint32_t    baseOfData;
  uint64_t    imageBase;
  uint32_t    sectionAlignment;
  uint32_t    fileAlignment;
  uint16_t    majorOSVer;
  uint16_t    minorOSVer;
  uint16_t 	  majorImageVer; 	
  uint16_t 	  minorImageVer;	
  uint16_t 	  majorSubsystemVer; 
  uint16_t 	  minorSubsystemVer; 
  uint32_t 	  win32VersionVal; 	
  uint32_t 	  sizeOfImage; 		
  uint32_t 	  sizeOfHeaders; 		
  uint32_t 	  checkSum; 			
  uint16_t 	  subsystem; 			
  uint16_t 	  dllCharacteristics; 	
  uint64_t 	  sizeOfStackReserve; 	
  uint64_t 	  sizeOfStackCommit; 	
  uint64_t 	  sizeOfHeapReserve; 	
  uint64_t 	  sizeOfHeapCommit; 	
  uint32_t 	  loaderFlags; 		
  uint32_t 	  numberOfRvaAndSizes;
} optional_header_t;


// PE header
typedef struct pe_header_t{
  uint32_t          peOffset; 
  uint32_t          signature;   
  uint16_t          machine; 
  uint16_t          numberOfSections;
  uint32_t          timeStamp;
  uint32_t          symTablePtr;
  uint32_t          numberOfSym;
  uint16_t          optionalHeaderSize;
  uint16_t          characteristics;
  optional_header_t optionalHeader;
} pe_header_t;

// DOS header
typedef struct dos_header_t{
  uint16_t  magic;      // Magic DOS signature MZ 
  uint16_t  e_cblp;		  // Bytes on last page of file
  uint16_t  e_cp;		    // Pages in file
  uint16_t  e_crlc;		  // Relocations
  uint16_t	e_cparhdr;	// Size of header in paragraphs
  uint16_t	e_minalloc;	// Minimum extra paragraphs needed
  uint16_t	e_maxalloc;	// Maximum extra paragraphs needed
  uint16_t	e_ss;		    // nitial (relative) SS value
  uint16_t	e_sp;		    // Initial SP value
  uint16_t	e_csum;		  // Checksum
  uint16_t	e_ip;		    // Initial IP value
  uint16_t	e_cs;		    // Initial (relative) CS value
  uint16_t	e_lfarlc;	  // File address of relocation table
  uint16_t	e_ovno;		  // Overloay number
  uint64_t	e_res;	    // Reserved uint16_ts (4 uint16_ts)
  uint16_t	e_oemid;		// OEM identifier (for e_oeminfo)
  uint16_t	e_oeminfo;	// OEM information; e_oemid specific
  uint64_t	e_res2;	    // Reserved uint16_ts (10 uint16_ts)
  uint32_t  e_lfanew;   // Offset to start of PE header 
  pe_header_t         pe;
  section_table_t    *section_table;
  data_directory_t   *dataDirectory;
  export_directory_t  exportDir;
  import_directory_t  *importDir;
  // to be implemented later:
  //    resources directory
  //    base relocation table
  //    debug table
  //    tls table
  //    load config table
  //    delay import descriptor
}dos_header_t;

// misc functions to help with the general parsing operations
uint64_t  rva_to_offset(int numberOfSections, uint64_t rva, 
                           section_table_t *sections);

// functions to output PE info
void      print_pe_characteristics(uint16_t ch);
void      print_machine(uint16_t mach);
void      print_magic(uint16_t magic);
void      print_subsystem(uint16_t system);
void      print_dllcharacteristics(uint16_t ch);
void      print_section_characteristics(uint32_t ch);
void      print_exports(dos_header_t *dosHeader);
void      print_imports(dos_header_t *dosHeader);

// functions to parse section from PE file
void      read_dos(FILE *in, dos_header_t *dosHeader);
void      read_pe(FILE *in, dos_header_t *dosHeader);
void      read_dataDir(FILE *in, dos_header_t *dosHeader);
void      read_sections(FILE *in, dos_header_t *dosHeader);
void      read_dataOffset(dos_header_t *dosHeader);
void      read_exportDir(FILE *in, dos_header_t *dosHeader);
void      read_exportNames(FILE *in, dos_header_t *dosHeader);
void      read_importDir(FILE *in, dos_header_t *dosHeader);

// cleanup function
void      cleanup(dos_header_t *dosHeader);


// Machine types
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
#define IMAGE_FILE_MACHINE_UNKNOWN  0x0     // assumed to be applicable to any machine type
#define IMAGE_FILE_MACHINE_IA64   	0x200   // Intel Itanium processor family
#define IMAGE_FILE_MACHINE_I386   	0x14c   // Intel 386 or later processors and compatible processors
#define IMAGE_FILE_MACHINE_AMD64   	0x8664  // x64
#define IMAGE_FILE_MACHINE_ARM   		0x1c0   // ARM little endian
#define IMAGE_FILE_MACHINE_ARM64   	0xaa64  // ARM64 little endian
#define IMAGE_FILE_MACHINE_ARMNT   	0x1c4   // ARM Thumb-2 little endian
#define IMAGE_FILE_MACHINE_EBC   		0xebc   // EFI byte code

// PE optional image
#define OPTIONAL_IMAGE_PE32      0x10b
#define OPTIONAL_IMAGE_PE32_plus 0x20b

// Image subsystem
#define IMAGE_SUBSYSTEM_UNKNOWN   		  	0   		//  An unknown subsystem
#define IMAGE_SUBSYSTEM_NATIVE    		  	1   		//  Device drivers and native Windows processes
#define IMAGE_SUBSYSTEM_WINDOWS_GUI     	2  		 	//  The Windows graphical user interface (GUI) subsystem
#define IMAGE_SUBSYSTEM_WINDOWS_CUI     	3  		 	//  The Windows character subsystem
#define IMAGE_SUBSYSTEM_OS2_CUI     	  	5    		//  The OS/2 character subsystem
#define IMAGE_SUBSYSTEM_POSIX_CUI     		7    		//	The Posix character subsystem
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS    8  	    //  Native Win9x driver
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI   	9   		//  Windows CE
#define IMAGE_SUBSYSTEM_EFI_APPLICATION   10   		//  An Extensible Firmware Interface (EFI) application
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER    11   //  An EFI driver with boot services
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER     	   12   // 	An EFI driver with run-time services
#define IMAGE_SUBSYSTEM_EFI_ROM     		13      	    	//	An EFI ROM image
#define IMAGE_SUBSYSTEM_XBOX     			  14              //  XBOX
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16  //  Windows boot application. 

#endif