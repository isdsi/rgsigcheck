using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace rgsigcheck
{
    public class DLLExportViewer
    {
        #region APIs
        [DllImport("imagehlp.dll")]
        public static extern Boolean MapAndLoad(String ImageName, String DllPath, ref LOADED_IMAGE LoadedImage, Boolean DotDll, Boolean ReadOnly);

        [DllImport("imagehlp.dll")]
        public static extern Boolean UnMapAndLoad(ref LOADED_IMAGE LoadedImage);

        [DllImport("dbghelp.dll")]
        public static extern IntPtr ImageDirectoryEntryToData(IntPtr Base, Boolean MappedAsImage, UInt16 DirectoryEntry, ref Int32 Size);

        [DllImport("dbghelp.dll")]
        public static extern IntPtr ImageRvaToVa(ref IMAGE_NT_HEADERS NtHeaders, IntPtr Base, UInt32 Rva, ref IMAGE_SECTION_HEADER LastRvaSection);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateFile(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, UInt32 lpSecurityAttributes, 
            UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, UInt32 hTemplateFile);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateFileMapping(IntPtr hFile, ref SECURITY_ATTRIBUTES lpFileMappingAttributes, UInt32 flProtect, UInt32 dwMaximumSizeHigh, 
            UInt32 dwMaximumSizeLow, ref String lpName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFileEx(IntPtr hFileMappingObject, UInt32 dwDesiredAccess, UInt32 dwFileOffsetHigh, UInt32 dwFileOffsetLow, 
            UInt32 dwNumberOfBytesToMap, IntPtr lpBaseAddress);

        [DllImport("dbghelp.dll")]
        public static extern IntPtr ImageNtHeader(IntPtr Base);
        #endregion

        #region Structures
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LOADED_IMAGE
        {
            public String ModuleName;
            public IntPtr hFile;
            public IntPtr MappedAddress;
            public IMAGE_NT_HEADERS FileHeader;
            public IMAGE_SECTION_HEADER LastRvaSection;
            public Int32 NumberOfSections;
            public IMAGE_SECTION_HEADER Sections;
            public Int32 Characteristics;
            public Boolean fSystemImage;
            public Boolean fDOSImage;
            public LIST_ENTRY Links;
            public Int32 SizeOfImage;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;
            public UInt32 AddressOfNames;
            public UInt32 AddressOfOrdinals;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_NT_HEADERS
        {
            public Int32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = IMAGE_SIZEOF_SHORT_NAME)]
            public Byte[] Name;
            public Misc Misc;
            public UInt32 PhysicalAddress;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLinenumbers;
            public Int16 NumberOfRelocations;
            public Int16 NumberOfLinenumbers;
            public UInt32 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_OPTIONAL_HEADER
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct Misc
        {
            [FieldOffset(0)]
            public UInt32 PhysicalAddress;
            [FieldOffset(0)]
            public UInt32 VirtualSize;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct SECURITY_ATTRIBUTES {
            UInt32 nLength;
            IntPtr lpSecurityDescriptor;
            Boolean bInheritHandle;
        } 
        #endregion

        #region Variables & Constants
        public const Int32 IMAGE_SIZEOF_SHORT_NAME = 8;
        public const Int32 IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
        public const UInt16 IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

        public const UInt32 GENERIC_READ      = 0x80000000;
        public const UInt32 GENERIC_WRITE     = 0x40000000;
        public const UInt32 GENERIC_EXECUTE   = 0x20000000;
        public const UInt32 GENERIC_ALL       = 0x10000000;

        public const UInt32 CREATE_NEW        = 1;
        public const UInt32 CREATE_ALWAYS     = 2;
        public const UInt32 OPEN_EXISTING     = 3;
        public const UInt32 OPEN_ALWAYS       = 4;
        public const UInt32 TRUNCATE_EXISTING = 5;

        public const UInt32 FILE_ATTRIBUTE_NORMAL = 0x00000080;

        public const UInt32 PAGE_NOACCESS     = 0x01;
        public const UInt32 PAGE_READONLY     = 0x02;
        public const UInt32 PAGE_READWRITE    = 0x04;
        public const UInt32 PAGE_WRITECOPY    = 0x08;

        public const UInt32 FILE_MAP_WRITE    = 0x0002;
        public const UInt32 FILE_MAP_READ     = 0x0004;

        public const UInt32 IMAGE_FILE_RELOCS_STRIPPED           = 0x0001;  // Relocation info stripped from file.
        public const UInt32 IMAGE_FILE_EXECUTABLE_IMAGE          = 0x0002;  // File is executable  (i.e. no unresolved external references).
        public const UInt32 IMAGE_FILE_LINE_NUMS_STRIPPED        = 0x0004;  // Line nunbers stripped from file.
        public const UInt32 IMAGE_FILE_LOCAL_SYMS_STRIPPED       = 0x0008;  // Local symbols stripped from file.
        public const UInt32 IMAGE_FILE_AGGRESIVE_WS_TRIM         = 0x0010;  // Aggressively trim working set
        public const UInt32 IMAGE_FILE_LARGE_ADDRESS_AWARE       = 0x0020;  // App can handle >2gb addresses
        public const UInt32 IMAGE_FILE_BYTES_REVERSED_LO         = 0x0080;  // Bytes of machine word are reversed.
        public const UInt32 IMAGE_FILE_32BIT_MACHINE             = 0x0100;  // 32 bit word machine.
        public const UInt32 IMAGE_FILE_DEBUG_STRIPPED            = 0x0200;  // Debugging info stripped from file in .DBG file
        public const UInt32 IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   = 0x0400;  // If Image is on removable media, copy and run from the swap file.
        public const UInt32 IMAGE_FILE_NET_RUN_FROM_SWAP         = 0x0800;  // If Image is on Net, copy and run from the swap file.
        public const UInt32 IMAGE_FILE_SYSTEM                    = 0x1000;  // System File.
        public const UInt32 IMAGE_FILE_DLL                       = 0x2000;  // File is a DLL.
        public const UInt32 IMAGE_FILE_UP_SYSTEM_ONLY            = 0x4000;  // File should only be run on a UP machine
        public const UInt32 IMAGE_FILE_BYTES_REVERSED_HI         = 0x8000;  // Bytes of machine word are reversed.
        public const UInt32 IMAGE_FILE_MACHINE_UNKNOWN           = 0;
        public const UInt32 IMAGE_FILE_MACHINE_TARGET_HOST       = 0x0001;  // Useful for indicating we want to interact with the host and not a WoW guest.
        public const UInt32 IMAGE_FILE_MACHINE_I386              = 0x014c;  // Intel 386.
        public const UInt32 IMAGE_FILE_MACHINE_R3000             = 0x0162;  // MIPS little-endian, 0x160 big-endian
        public const UInt32 IMAGE_FILE_MACHINE_R4000             = 0x0166;  // MIPS little-endian
        public const UInt32 IMAGE_FILE_MACHINE_R10000            = 0x0168;  // MIPS little-endian
        public const UInt32 IMAGE_FILE_MACHINE_WCEMIPSV2         = 0x0169;  // MIPS little-endian WCE v2
        public const UInt32 IMAGE_FILE_MACHINE_ALPHA             = 0x0184;  // Alpha_AXP
        public const UInt32 IMAGE_FILE_MACHINE_SH3               = 0x01a2;  // SH3 little-endian
        public const UInt32 IMAGE_FILE_MACHINE_SH3DSP            = 0x01a3;
        public const UInt32 IMAGE_FILE_MACHINE_SH3E              = 0x01a4;  // SH3E little-endian
        public const UInt32 IMAGE_FILE_MACHINE_SH4               = 0x01a6;  // SH4 little-endian
        public const UInt32 IMAGE_FILE_MACHINE_SH5               = 0x01a8;  // SH5
        public const UInt32 IMAGE_FILE_MACHINE_ARM               = 0x01c0;  // ARM Little-Endian
        public const UInt32 IMAGE_FILE_MACHINE_THUMB             = 0x01c2;  // ARM Thumb/Thumb-2 Little-Endian
        public const UInt32 IMAGE_FILE_MACHINE_ARMNT             = 0x01c4;  // ARM Thumb-2 Little-Endian
        public const UInt32 IMAGE_FILE_MACHINE_AM33              = 0x01d3;
        public const UInt32 IMAGE_FILE_MACHINE_POWERPC           = 0x01F0;  // IBM PowerPC Little-Endian
        public const UInt32 IMAGE_FILE_MACHINE_POWERPCFP         = 0x01f1;
        public const UInt32 IMAGE_FILE_MACHINE_IA64              = 0x0200;  // Intel 64
        public const UInt32 IMAGE_FILE_MACHINE_MIPS16            = 0x0266;  // MIPS
        public const UInt32 IMAGE_FILE_MACHINE_ALPHA64           = 0x0284;  // ALPHA64
        public const UInt32 IMAGE_FILE_MACHINE_MIPSFPU           = 0x0366;  // MIPS
        public const UInt32 IMAGE_FILE_MACHINE_MIPSFPU16         = 0x0466;  // MIPS
        public const UInt32 IMAGE_FILE_MACHINE_AXP64             = IMAGE_FILE_MACHINE_ALPHA64;
        public const UInt32 IMAGE_FILE_MACHINE_TRICORE           = 0x0520;  // Infineon
        public const UInt32 IMAGE_FILE_MACHINE_CEF               = 0x0CEF;
        public const UInt32 IMAGE_FILE_MACHINE_EBC               = 0x0EBC;  // EFI Byte Code
        public const UInt32 IMAGE_FILE_MACHINE_AMD64             = 0x8664;  // AMD64 (K8)
        public const UInt32 IMAGE_FILE_MACHINE_M32R              = 0x9041;  // M32R little-endian
        public const UInt32 IMAGE_FILE_MACHINE_ARM64             = 0xAA64;  // ARM64 Little-Endian
        public const UInt32 IMAGE_FILE_MACHINE_CEE               = 0xC0EE;

        /// <summary>
        /// String value holding the path to the DLL file. This value is also returned by the FileName property.
        /// </summary>
        private String sDLLFilePath;

        /// <summary>
        /// Boolean value that is return by the LibraryLoaded property.
        /// </summary>
        private Boolean bLibraryLoaded;

        /// <summary>
        /// Int32 value that is returned by the FunctionCount property.
        /// </summary>
        private Int32 iFunctionCount;

        /// <summary>
        /// Int32 value that is returned by the SizeOfImage property.
        /// </summary>
        private Int32 iSizeOfCode;

        /// <summary>
        /// String array value that is returned by the ImageFunctions property.
        /// </summary>
        private String[] sFunctions;
        #endregion

        #region Properties
        /// <summary>
        /// Gets a boolean value indicating if the library has been loaded successfully.
        /// </summary>
        public Boolean LibraryLoaded { get { return bLibraryLoaded; } }

        /// <summary>
        /// Gets a string value indicating what file the class was initialized with.
        /// </summary>
        public String FileName { get { return sDLLFilePath; } }

        /// <summary>
        /// Gets a string array of the functions within the image.
        /// </summary>
        public String[] ImageFunctions { get { return sFunctions; } }

        /// <summary>
        /// Gets an Int32 value indicating the number of functions within the image.
        /// </summary>
        public Int32 FunctionCount { get { return iFunctionCount; } }
        #endregion

        /// <summary>
        /// Initilizes the DLLExportViewer class.
        /// </summary>
        /// <param name="sFilePath">Path to the DLL file to initilize the class with.</param>
        /*
        public DLLExportViewer(String sFilePath)
        {
            IMAGE_SECTION_HEADER ishSectionHeader = new IMAGE_SECTION_HEADER();
            LOADED_IMAGE liLoadedImage = new LOADED_IMAGE();
            IMAGE_EXPORT_DIRECTORY iedExportDirectory;
            IntPtr pImageExportDirectory;
            IntPtr pVirtualAddressOfNames;
            Int32 iDirectoryExportSize = 0;

            sDLLFilePath = sFilePath;

            if (MapAndLoad(sDLLFilePath, null, ref liLoadedImage, true, true))
            {
                bLibraryLoaded = true;

                pImageExportDirectory = ImageDirectoryEntryToData(liLoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, ref iDirectoryExportSize);
                if (pImageExportDirectory == IntPtr.Zero)
                {
                    Console.WriteLine(String.Format("Error Number:{0}\nError:{1}", Marshal.GetLastWin32Error(), new Win32Exception(Marshal.GetLastWin32Error()).Message));
                }
                iedExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(pImageExportDirectory, typeof(IMAGE_EXPORT_DIRECTORY));

                iFunctionCount = (Int32)iedExportDirectory.NumberOfFunctions;

                pVirtualAddressOfNames = ImageRvaToVa(ref liLoadedImage.FileHeader, liLoadedImage.MappedAddress, iedExportDirectory.AddressOfNames, ref ishSectionHeader);
            }
            else
            {
                throw new Exception(String.Format("Failed to load library {0}\n\nError Number:{1]\nError:{2}", sDLLFilePath, Marshal.GetLastWin32Error(), new Win32Exception(Marshal.GetLastWin32Error()).Message));
            }
        }
        */

        public DLLExportViewer(String path)
        {
            IntPtr hFile = CreateFile(path, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            String name = "";
            IntPtr hMap = CreateFileMapping(
                hFile,
                ref sa,           // security attrs
                PAGE_READONLY,  // protection flags
                0,              // max size - high DWORD
                0,              // max size - low DWORD      
                ref name);         // mapping name - not used

            // next, map the file to our address space
            IntPtr hPtr = new IntPtr();
            IntPtr mapAddr = MapViewOfFileEx(
                hMap,             // mapping object
                FILE_MAP_READ,  // desired access
                0,              // loc to map - hi DWORD
                0,              // loc to map - lo DWORD
                0,              // #bytes to map - 0=all
                hPtr);         // suggested map addr
            if (mapAddr == IntPtr.Zero)
            {
                Console.WriteLine("MapViewOfFileEx Failed.");
                return;
            }
            IMAGE_NT_HEADERS inh = new IMAGE_NT_HEADERS(); 
            IntPtr HeaderPointer = ImageNtHeader(mapAddr);
            if (HeaderPointer == IntPtr.Zero)
            {
                Console.WriteLine("ImageNtHeader Failed.");
                return;
            }

            IMAGE_NT_HEADERS Header = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(HeaderPointer, typeof(IMAGE_NT_HEADERS));
            string sMachine = "";
            switch((uint)Header.FileHeader.Machine)
            {
                case IMAGE_FILE_MACHINE_UNKNOWN: sMachine = "The content of this field is assumed to be applicable to any machine type"; break;
                case IMAGE_FILE_MACHINE_ALPHA: sMachine = "Alpha AXP, 32 - bit address space"; break;
                case IMAGE_FILE_MACHINE_ALPHA64: sMachine = "Alpha 64, 64 - bit address space"; break;
                case IMAGE_FILE_MACHINE_AM33: sMachine = "Matsushita AM33"; break;
                case IMAGE_FILE_MACHINE_AMD64: sMachine = "x64"; break;
                case IMAGE_FILE_MACHINE_ARM: sMachine = "ARM little endian"; break;
                case IMAGE_FILE_MACHINE_ARM64: sMachine = "ARM64 little endian"; break;
                case IMAGE_FILE_MACHINE_ARMNT: sMachine = "ARM Thumb - 2 little endian"; break;
                //case IMAGE_FILE_MACHINE_AXP64: sMachine = "AXP 64 (Same as Alpha 64)"; break;
                case IMAGE_FILE_MACHINE_EBC: sMachine = "EFI byte code"; break;
                case IMAGE_FILE_MACHINE_I386: sMachine = "Intel 386 or later processors and compatible processors"; break;
                case IMAGE_FILE_MACHINE_IA64: sMachine = "Intel Itanium processor family"; break;
                case IMAGE_FILE_MACHINE_M32R: sMachine = "Mitsubishi M32R little endian"; break;
                case IMAGE_FILE_MACHINE_MIPS16: sMachine = "MIPS16"; break;
                case IMAGE_FILE_MACHINE_MIPSFPU: sMachine = "MIPS with FPU"; break;
                case IMAGE_FILE_MACHINE_MIPSFPU16: sMachine = "MIPS16 with FPU"; break;
                case IMAGE_FILE_MACHINE_POWERPC: sMachine = "Power PC little endian"; break;
                case IMAGE_FILE_MACHINE_POWERPCFP: sMachine = "Power PC with floating point support"; break;
                case IMAGE_FILE_MACHINE_R4000: sMachine = "MIPS little endian"; break;
                case IMAGE_FILE_MACHINE_SH3: sMachine = "Hitachi SH3"; break;
                case IMAGE_FILE_MACHINE_SH3DSP: sMachine = "Hitachi SH3 DSP"; break;
                case IMAGE_FILE_MACHINE_SH4: sMachine = "Hitachi SH4"; break;
                case IMAGE_FILE_MACHINE_SH5: sMachine = "Hitachi SH5"; break;
                case IMAGE_FILE_MACHINE_THUMB: sMachine = "Thumb"; break;
                case IMAGE_FILE_MACHINE_WCEMIPSV2: sMachine = "MIPS little - endian WCE v2"; break;
                default: sMachine = "Unknown"; break;
            }
            Console.WriteLine("Image File Machine: " + sMachine);
        }

    }
}
