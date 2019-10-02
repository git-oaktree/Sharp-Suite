using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Colorful;
using Console = Colorful.Console;
using System.Drawing;


namespace DesertNut
{
    class DesertNut_h
    {

        // Banner
        //-----------------------------------
        public static void PrintBanner()
        {
            Console.ForegroundColor = Color.Orange;
            Console.WriteLine("           ,                        '           .        '        ,        ");
            Console.WriteLine("   .            .        '       .         ,                               ");
            Console.WriteLine("                                                   .       '     +         ");
            Console.WriteLine("       +          .-'''''-.                                                ");
            Console.WriteLine("                .'         `.   +     .     ________||                     ");
            Console.WriteLine("       ___     :             :     |       /        ||  .     '___         ");
            Console.WriteLine("  ____/   \\   :               :   ||.    _/      || ||\\_______/   \\     ");
            Console.WriteLine(" /         \\  :      _/|      :   `|| __/      ,.|| ||             \\     ");
            Console.WriteLine("/  ,   '  . \\  :   =/_/      :     |'_______     || ||  ||   .      \\    ");
            Console.WriteLine("    |        \\__`._/ |     .'   ___|        \\__   \\\\||  ||...    ,   \\");
            Console.WriteLine("   l|,   '   (   /  ,|...-'        \\   '   ,     __\\||_//___             ");
            Console.WriteLine(" ___|____     \\_/^\\/||__    ,    .  ,__             ||//    \\    .  ,   ");
            Console.WriteLine("           _/~  `''~`'` \\_           ''(       ....,||/       '           ");
            Console.WriteLine(" ..,...  __/  -'/  `-._ `\\_\\__        | \\           ||  _______   .     ");
            Console.WriteLine("              '`  `\\   \\  \\-.\\        /(_1_,..      || /               ");
            Console.WriteLine("                                            ______/''''                  \n");
            Console.ResetColor();
        }

        // Globals
        //-----------------------------------
        public static List<WndPropStruc> SubclassWndProps = new List<WndPropStruc>();
        public static WndPropStruc TargetSubclass = new WndPropStruc();
        public static Formatter[] sProperties =
        {
            new Formatter("[>]", Color.LightGreen),
            new Formatter(":", Color.LightGreen),
            new Formatter("|->", Color.LightGreen),
            new Formatter(",", Color.LightGreen),
            new Formatter("PID", Color.Orange),
            new Formatter("ImageName", Color.Orange),
            new Formatter("hProperty", Color.Orange),
            new Formatter("hParentWnd", Color.Orange),
            new Formatter("hChildWnd", Color.Orange),
            new Formatter("ParentClassName", Color.Orange),
            new Formatter("ChildClassName", Color.Orange),
        };
        public static Formatter[] iProperties =
        {
            new Formatter("[>]", Color.LightGreen),
            new Formatter(":", Color.LightGreen),
            new Formatter("|->", Color.LightGreen),
            new Formatter(",", Color.LightGreen),
            new Formatter("-->", Color.LightGreen),
            new Formatter("hProc", Color.Orange),
            new Formatter("hProperty", Color.Orange),
            new Formatter("uRefs", Color.Orange),
            new Formatter("uAlloc", Color.Orange),
            new Formatter("uCleanup", Color.Orange),
            new Formatter("dwThreadId", Color.Orange),
            new Formatter("pFrameCur", Color.Orange),
            new Formatter("pfnSubclass", Color.Orange),
            new Formatter("uIdSubclass", Color.Orange),
            new Formatter("dwRefData", Color.Orange),
            new Formatter("Sc Len", Color.Orange),
            new Formatter("Sc Address", Color.Orange),
            new Formatter("Subclass header Len", Color.Orange),
            new Formatter("Subclass header Address", Color.Orange),
        };

        // Structs
        //-----------------------------------
        [StructLayout(LayoutKind.Sequential)]
        public struct WndPropStruc
        {
            public UInt32 dwPid;
            public String ImageName;
            public IntPtr hProperty;
            public IntPtr hParentWnd;
            public IntPtr hChildWnd;
            public String ParentClassName;
            public String ChildClassName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SUBCLASS_HEADER
        {
            public UInt32 uRefs;
            public UInt32 uAlloc;
            public UInt32 uCleanup;
            public UInt32 dwThreadId;
            public IntPtr pFrameCur;
            public SUBCLASS_CALL CallArray;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SUBCLASS_FRAME
        {
            public UInt32 uCallIndex;
            public UInt32 uDeepestCall;
            public IntPtr pFramePrev;
            public IntPtr pHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SUBCLASS_CALL
        {
            public IntPtr pfnSubclass;
            public UIntPtr uIdSubclass;
            public UIntPtr dwRefData;
        }

        // APIs
        //-----------------------------------
        [DllImport("user32.dll")]
        public static extern bool EnumWindows(
            WindowCallBack callback, 
            int lParam);

        [DllImport("user32.dll")]
        public static extern bool EnumChildWindows(
            IntPtr window, 
            WindowCallBack callback, 
            IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern int EnumProps(
            IntPtr hwnd, 
            PropEnumPropCallBack lpEnumFunc);

        [DllImport("user32.dll")]
        public static extern IntPtr GetProp(
            IntPtr hWnd, 
            String lpString);

        [DllImport("user32.dll")]
        public static extern bool SetProp(
            IntPtr hWnd, 
            string lpString, 
            IntPtr hData);

        [DllImport("user32.dll")]
        public static extern bool PostMessage(
            IntPtr hWnd, 
            uint Msg, 
            IntPtr wParam, 
            IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(
            IntPtr hWnd, 
            ref UInt32 ProcessId);

        [DllImport("user32.dll")]
        public static extern IntPtr GetParent(
            IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern int GetClassName(
            IntPtr hWnd, 
            StringBuilder lpClassName, 
            int nMaxCount);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 processAccess, 
            bool bInheritHandle, 
            int processId);

        [DllImport("kernel32.dll")]
        public static extern Boolean ReadProcessMemory(
            IntPtr hProcess, 
            IntPtr lpBaseAddress, 
            IntPtr lpBuffer, 
            UInt32 dwSize, 
            ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            int flAllocationType,
            int flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            UInt32 dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern Boolean CloseHandle(
            IntPtr hObject);

        // Callbacks
        //-----------------------------------
        public delegate bool WindowCallBack(IntPtr hwnd, IntPtr lParam);
        public delegate bool PropEnumPropCallBack(IntPtr hwnd, IntPtr lpszString, IntPtr hData);

        // Shellcode
        // Function prototype should be:
        // typedef LRESULT (CALLBACK *SUBCLASSPROC)(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
        // ==> https://github.com/odzhan/injection/blob/master/payload/x64/payload.c
        // Below was compiled for x64 only!
        //-----------------------------------
   
        

        // Helpers
        //-----------------------------------
        public static Boolean EnumWndProps(IntPtr hwnd, IntPtr lpszString, IntPtr hData)
        {
            // Create result struct
            WndPropStruc PropertyStruct = new WndPropStruc();
            // Fill struct data
            IntPtr UxSubclass = GetProp(hwnd, "UxSubclassInfo");
            IntPtr CC32Subclass = GetProp(hwnd, "CC32SubclassInfo");
            if (UxSubclass == IntPtr.Zero && CC32Subclass == IntPtr.Zero)
            {
                // This doesn't have what we need..
            } else
            {
                // Parse data
                if (UxSubclass == IntPtr.Zero)
                {
                    PropertyStruct.hProperty = CC32Subclass;
                }
                else
                {
                    PropertyStruct.hProperty = UxSubclass;
                }
                PropertyStruct.hChildWnd = hwnd;
                PropertyStruct.hParentWnd = GetParent(hwnd);
                GetWindowThreadProcessId(hwnd, ref PropertyStruct.dwPid);
                StringBuilder ParentClassName = new StringBuilder(260);
                GetClassName(PropertyStruct.hParentWnd, ParentClassName, 260);
                PropertyStruct.ParentClassName = ParentClassName.ToString();
                StringBuilder ChildClassName = new StringBuilder(260);
                GetClassName(PropertyStruct.hChildWnd, ChildClassName, 260);
                PropertyStruct.ChildClassName = ChildClassName.ToString();
                PropertyStruct.ImageName = Process.GetProcessById((int)PropertyStruct.dwPid).ProcessName;

                // if unique add to list
                if (!SubclassWndProps.Any(Entry => Entry.hProperty == PropertyStruct.hProperty))
                {
                    SubclassWndProps.Add(PropertyStruct);
                }
            }

            return true;
        }

        public static Boolean EnumChildWnd(IntPtr hwnd, IntPtr lParam)
        {
            EnumProps(hwnd, new PropEnumPropCallBack(EnumWndProps));
            return true;
        }

        public static Boolean EnumWnd(IntPtr hwnd, IntPtr lParam)
        {
            EnumChildWindows(hwnd, new WindowCallBack(EnumChildWnd), (IntPtr)0);
            EnumProps(hwnd, new PropEnumPropCallBack(EnumWndProps));
            return true;
        }

        public static List<WndPropStruc> EnumSubClassProps(Boolean List)
        {
            EnumWindows(new WindowCallBack(EnumWnd), 0);
            if (SubclassWndProps.Count > 0)
            {
                if (List)
                {
                    Console.WriteLine("\n[+] Subclassed Window Properties", Color.LightGreen);
                    foreach (WndPropStruc SubClass in SubclassWndProps)
                    {
                        Console.WriteLineFormatted("{0} {4}{1} " + SubClass.dwPid + "{3} {5}{1} " + SubClass.ImageName, Color.White, sProperties);
                        Console.WriteLineFormatted("    {2} {6}{1} " + "0x" + String.Format("{0:X}", (SubClass.hProperty).ToInt64()) + "{3} {7}{1} " + "0x" + String.Format("{0:X}", (SubClass.hParentWnd).ToInt64()) + "{3} {8}{1} " + "0x" + String.Format("{0:X}", (SubClass.hChildWnd).ToInt64()), Color.White, sProperties);
                        Console.WriteLineFormatted("    {2} {9}{1} " + SubClass.ParentClassName + "{3} {10}{1} " + SubClass.ChildClassName + "\n", Color.White, sProperties);
                    }
                }
            }
            return SubclassWndProps;
        }

        public static IntPtr ReadSubclassHeader(WndPropStruc UxSubclassInfo)
        {
            // Open process
            Console.WriteLine("[+] Duplicating Subclass header..", Color.LightGreen);
            IntPtr hProc = OpenProcess(0x1F0FFF, false, (int)UxSubclassInfo.dwPid);
            if (hProc == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to open " + UxSubclassInfo.ImageName + " for access.." , Color.Red);
                return IntPtr.Zero;
            } else
            {
                Console.WriteLineFormatted("{0} {5}{1} " + "0x" + String.Format("{0:X}", (hProc).ToInt64()), Color.White, iProperties);
            }

            // Read out header
            SUBCLASS_HEADER SubclassHeader = new SUBCLASS_HEADER();
            IntPtr HeaderCopy = Marshal.AllocHGlobal(Marshal.SizeOf(SubclassHeader));
            uint BytesRead = 0;
            Boolean CallResult = ReadProcessMemory(hProc, UxSubclassInfo.hProperty, HeaderCopy, (uint)(Marshal.SizeOf(SubclassHeader)), ref BytesRead);
            if (CallResult)
            {
                Console.WriteLineFormatted("{0} {6}{1} " + "0x" + String.Format("{0:X}", (UxSubclassInfo.hProperty).ToInt64()), Color.White, iProperties);
                SubclassHeader = (SUBCLASS_HEADER)Marshal.PtrToStructure(HeaderCopy, typeof(SUBCLASS_HEADER));
                Console.WriteLineFormatted("    {2} {7}{1} " + SubclassHeader.uRefs + "{3} {8}{1} " + SubclassHeader.uAlloc + "{3} {9}{1} " + SubclassHeader.uCleanup, Color.White, iProperties);
                Console.WriteLineFormatted("    {2} {10}{1} " + SubclassHeader.dwThreadId + "{3} {11}{1} " + SubclassHeader.pFrameCur, Color.White, iProperties);
                Console.WriteLineFormatted("    {2} {12}{1} " + "0x" + String.Format("{0:X}", (SubclassHeader.CallArray.pfnSubclass).ToInt64()) + " {4} comctl32!CallOriginalWndProc (?)", Color.White, iProperties);
                Console.WriteLineFormatted("    {2} {13}{1} " + SubclassHeader.CallArray.uIdSubclass + "{3} {14}{1} " + "0x" + String.Format("{0:X}", (Int64)SubclassHeader.CallArray.dwRefData), Color.White, iProperties);
            } else
            {
                Console.WriteLine("[!] Unable to call ReadProcessMemory..", Color.Red);
                CloseHandle(hProc);
                return IntPtr.Zero;
            }

            CloseHandle(hProc);
            return HeaderCopy;
        }
    }
}
