PE Parser

## Introduction
A parser for the PE (Portable Executable) format of executable files and dynamic libraries under Windows. It is able to parse DLL or EXE files, extract and produce information about the file, such as its version, entries found in its import table or resources. 

Some of the files that use PE headers includes:
.acm, .ax, .cpl, .dll, .drv, .efi, .exe, .mui, .ocx, .scr, .sys, .tsp


## Building / Compiling / Running
The source code can be compiled and run on both Linux/Windows, using either gcc or Visual Studio (tested on Visual Studio 2015).

On Linux you can build and run the program in following steps.

```
$ git clone https://github.com/adabz/PE-Parser
$ cd PE-Parser/
$ make
$ ./peparser ../samples-pe/tier0_s.dll 
showing file: ../samples-pe/tier0_s.dll 

Magic bytes:            MZ
PE Offset               110

PE header information
 Signature:             0x4550 (PE) 
 Machine:               (14C)  IMAGE_FILE_MACHINE_I386
 Sections:              5
 Time Stamp:            0x6198109D
 Symbol Table Pointer:  0x0
 Symbols:               0
 OpionalHeader Size:    224 (0xE0)
 Characteristics:       0x2102
     IMAGE_FILE_EXECUTABLE_IMAGE
     IMAGE_FILE_32BIT_MACHINE
     IMAGE_FILE_DLL

Optional Header
Magic:      10B (PE) 
MajorLinkerVersion:      0xE
MinorLinkerVersion:      0x1D
SizeOfCode:              0x36E00
SizeOfInitializedData:   0x1C200
SizeOfUninitializedData: 0x0
EntryPoint:              0x1B1CC
BaseOfCode:              0x1000
BaseOfData:              0x38000
ImageBase:               0x3f000000
SectionAlignment:        0x1000
FileAlignment:           0x200
MajorOSVersion:          0x6
MinorOSVersion:          0x0
MajorImageVersion:       0x0
MinorImageVersion:       0x0
MajorSubsysVersion:      0x6
MinorSubsysVersion:      0x0
Win32VersionValue:       0x0
SizeOfImage:             0x9A000
SizeOfHeaders:           0x400
CheckSum:                0x61CF1
Subsystem:               (2)   IMAGE_SUBSYSTEM_WINDOWS_GUI
DllCharacteristics:           
     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
     IMAGE_DLLCHARACTERISTICS_NX_COMPAT
SizeOfStackReserve:      0x100000
SizeOfStackCommit:       0x1000
SizeOfHeapReserve:       0x100000
SizeOfHeapCommit:        0x1000
LoaderFlags:             0x0
NumberOfRvaAndSizes:     16

Data Tables: 
  Export Table: 
     Address: 0x438F0   Offset: 42AF0
        Size: 0x4DB4 
  Import Table: 
     Address: 0x486A4   Offset: 478A4
        Size: 0x78 
  Resource Table: 
     Address: 0x96000   Offset: 4F800
        Size: 0xC8C 
  Certificate : 
     Address: 0x53400   Offset: FFFFFFFF
        Size: 0x23A8 
  Base Relocation: 
     Address: 0x97000   Offset: 50600
        Size: 0x2C34 
  Debug Table: 
     Address: 0x41C70   Offset: 40E70
        Size: 0x54 
  TLS Table: 
     Address: 0x41DC0   Offset: 40FC0
        Size: 0x18 
  Load Config : 
     Address: 0x41CC8   Offset: 40EC8
        Size: 0x40 
  Import Address: 
     Address: 0x38000   Offset: 37200
        Size: 0x30C 

Sections: 
   Name: .text
       VirtualAddress:        1000
       VirtualSize:           36DEA
       SizeOfRawData:         36E00
       PointerToRawData:      400
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       60000020
          IMAGE_SCN_CNT_CODE
          IMAGE_SCN_MEM_EXECUTE
          IMAGE_SCN_MEM_READ
   Name: .rdata
       VirtualAddress:        38000
       VirtualSize:           11830
       SizeOfRawData:         11A00
       PointerToRawData:      37200
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .data
       VirtualAddress:        4A000
       VirtualSize:           4B414
       SizeOfRawData:         6C00
       PointerToRawData:      48C00
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       C0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .rsrc
       VirtualAddress:        96000
       VirtualSize:           C8C
       SizeOfRawData:         E00
       PointerToRawData:      4F800
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .reloc
       VirtualAddress:        97000
       VirtualSize:           2C34
       SizeOfRawData:         2E00
       PointerToRawData:      50600
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       42000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_DISCARDABLE
          IMAGE_SCN_MEM_READ

Export Directory 
    Flags:           0x0
    TimeStamp:       0xFFFFFFFF
    MajorVersion:    0x0
    MinorVersion:    0x0
    Name RVA:        0x44D22
    OrdinalBase:     0x1
    AddressTable Entries:  0x201
    NumberOfNames:         0x201
    ExportTable Entries:   0x43918
    AddressOfNames:        0x4411C
    OrdinalTable RVA:      0x44920

Exported functions: 
       ??0CStack@@QAE@XZ
       ??0CThread@@QAE@XZ
       ??0CThreadEvent@@QAE@PAX_N@Z
       ??0CThreadEvent@@QAE@PBD_N1@Z

................. shortened for briefness ..................

       ?AssertUseable@CThreadSyncObject@@IAEXXZ
       ?AtRoot@CVProfile@@QBE_NXZ
       ?BCountingOnly@CValidator@@QAE_NXZ
       ?BExcludeAllocationFromTracking@CValidator@@AAE_NPBDH@Z
       ?BHasValidThreadID@CThread@@QBE_NXZ
       ?BIsProfilePtrValid@CVProfManager@@QAE_NPAVCVProfile@@@Z
       ?BLockForReadNoWait@CThreadRWLock@@QAE_NXZ
       ?BMemLeaks@CValidator@@QAE_NXZ
       ?BProfileHasNodesOutsideBudgetGroup_Recursive@CVProfile@@IAE_NPAVCVProfNode@@H@Z
       ?BoostPriority@CWorkerThread@@QAEHXZ
       ?BudgetGroupNameToBudgetGroupID@CVProfile@@QBE?AW4EVProfBugdetGroup@@PBD@Z
       ?CalcStackDepth@CThread@@QAEIPAX@Z
       ?CalculateCRC@CStack@@QAEXXZ
       AllocateCrashMemoryReserve
       AreStackTrackingFiltersEnabledAtStart
       AssertMsgImplementation
       AssertMsgImplementationF
       AssertMsgImplementationV
       BBlockingGetMiniDumpLock
       BGetLocalFQDN
       BGetMiniDumpLock
       BWritingFatalMiniDump
       BWritingMiniDump
       BWritingNonFatalMiniDump
       CVProfile_ExitScope
       CallAssertFailedNotifyFunc
       CallFlushLogFunc
       CatchAndWriteMiniDump
       CatchAndWriteMiniDumpEx
       CatchAndWriteMiniDumpExForVoidPtrFn
       CatchAndWriteMiniDumpExReturnsInt
       CatchAndWriteMiniDumpForVoidPtrFn
       ClearStackTrackingFilters
       ClearWritingMiniDump
       CopyFileUTF8
       CrackSmokingCompiler
       CreateDirectoryUTF8
       CreateFileUTF8
       CreateProcessUTF8
       CreateSimpleProcess
       DLog
       DWarning
       DeclareCurrentThreadIsMainThread
       DeleteFileUTF8
       DoNewAssertDialog
       ETWBegin
       ETWEnd
       ETWIsTracingEnabled
       ETWMark
       ETWMark1I
       ETWMark1S
       ETWMark2I
       ETWMark2S
       ETWMark3I
       ETWMarkPrintf
       ETWOverlayFrameMark
       ETWRenderFrameMark
       ETW_Steamworks_DispatchCallback_End_
       ETW_Steamworks_DispatchCallback_Start
...
```


## Resources
During the making of this program I've used:
- [aldeid wiki - PE-Portable-executable](https://www.aldeid.com/wiki/PE-Portable-executable)
- [Microsoft PE format documentation](
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Ange Albertini's Visual PE101 documentation of the PE format](
https://github.com/corkami/pics/tree/master/binary/pe101)
