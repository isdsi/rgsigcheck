using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace rgsigcheck
{
    namespace DLLMapper
{
class DLLExportViewer
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
        #endregion

        #region Variables & Constants
        public const Int32 IMAGE_SIZEOF_SHORT_NAME = 8;
        public const Int32 IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
        public const UInt16 IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

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
                iedExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(pImageExportDirectory, typeof(IMAGE_EXPORT_DIRECTORY));

                iFunctionCount = (Int32)iedExportDirectory.NumberOfFunctions;

                pVirtualAddressOfNames = ImageRvaToVa(ref liLoadedImage.FileHeader, liLoadedImage.MappedAddress, iedExportDirectory.AddressOfNames, ref ishSectionHeader);
            }
            else
            {
                throw new Exception(String.Format("Failed to load library {0}\n\nError Number:{1]\nError:{2}", sDLLFilePath, Marshal.GetLastWin32Error(), new Win32Exception(Marshal.GetLastWin32Error()).Message));
            }
        }
    }
}
    class Program
    {
        [DllImport("kernel32")]
        public static extern int GetBinaryType(string lpApplicationName, ref int lpBinaryType);

        [DllImport("kernel32")]
        public static extern int GetLastError();

        static void Main(string[] args)
        {            
            if (args.Length < 1)
            {
                Console.WriteLine("usage : rgsigcheck c:\\windows\\notepad.exe");
                return;
            }
            

            //string path = "C:\\Users\\ringo\\source\\console_prefer32bit_test\\bin\\Debug\\console_prefer32bit_test.exe"; // ILOnly, Preferred32Bit. I386, 32-bit Intel processor
            //string path = "c:\\windows\\notepad.exe"; // A 64-bit Windows-based application.
            //string path = "C:\\Users\\ringo\\source\\console_x64_x86_test\\Debug\\console_x64_x86_test.exe"; // A 32-bit Windows-based application
            //string path = "C:\\Users\\ringo\\source\\console_x64_x86_test\\x64\\Debug\\console_x64_x86_test.exe"; // A 32-bit Windows-based application
            //string path = "C:\\Users\\ringo\\source\\console_x86_x64_dll\\Debug\\console_x86_x64_dll.dll"; // Image File Machine: Intel 386 or later processors and compatible processors
            //string path = "C:\\Users\\ringo\\source\\console_x86_x64_dll\\x64\\Debug\\console_x86_x64_dll.dll"; // Image File Machine: x64
            string path = args[0];
            
            try
            {
                Assembly asm = Assembly.LoadFrom(path);
                //Assembly asm = Assembly.LoadFrom("C:\\Users\\ringo\\source\\rgsigcheck\\bin\\Debug\\rgsigcheck.exe");
                //Assembly asm = Assembly.LoadFrom("c:\\windows\\notepad.exe");
                //Assembly asm = Assembly.LoadFrom(args[0]);
                Console.WriteLine("this is an dotnet assembly.");
 
                PortableExecutableKinds peKind;
                ImageFileMachine machine;
 
                asm.ManifestModule.GetPEKind(out peKind, out machine);
                string sPEKind = $"{peKind}";
                if (sPEKind == "ILOnly")
                {
                    sPEKind += ", Not Preferred 32-bit";
                }
                
                Console.WriteLine("PE kind: " + sPEKind);
                
                string sMachine = $"{machine}";
                if (sMachine == "I386")
                {
                    sMachine += ", 32-bit Intel processor";
                }
                else if (sMachine == "AMD64")
                {
                    sMachine += ", 64-bit AMD processor";
                }
                Console.WriteLine("Machine: " + sMachine);
            } 
            catch(System.BadImageFormatException bife)
            {
                int bt = -1;
                if (GetBinaryType(path, ref bt) != 0)
                {
                    Console.WriteLine("this is an native exeutable.");
                
                    string s = "";
                    switch(bt)
                    {
                        case 0: s = "A 32-bit Windows-based application"; break;
                        case 6: s = "A 64-bit Windows-based application."; break;
                        case 1: s = "An MS-DOS – based application"; break;
                        case 5: s = "A 16-bit OS/2-based application"; break;
                        case 3: s = "A PIF file that executes an MS-DOS – based application"; break;
                        case 4: s = "A POSIX – based application"; break;
                        case 2: s = "A 16-bit Windows-based application"; break;
                        default : s = "Unknown application"; break;
                    }
                    Console.WriteLine(s);
                    return;
                }

                int le = GetLastError();
                Console.WriteLine("this is not runnable. GetLastError() = " + le.ToString());

                DLLExportViewer dllev = new DLLExportViewer(path);
                
            }

            Console.WriteLine("Press any key to stop...");
            Console.ReadKey();
        }
    }
}
