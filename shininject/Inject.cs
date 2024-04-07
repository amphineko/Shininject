using System;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;

namespace Shininject
{

    internal struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;

        public IntPtr AllocationBase;

        public uint AllocationProtect;

        public IntPtr RegionSize;

        public uint State;

        public uint Protect;

        public uint Type;
    }

    internal class Win32
    {
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;

        public const uint PROCESS_VM_READ = 0x0010;

        public const uint PAGE_NOACCESS = 0x01;

        public const uint PAGE_GUARD = 0x100;

        public const uint MEM_COMMIT = 0x1000;

        public const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x1000;

        public const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x200;

        public const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100;


        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        // GetLastError
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        // FormatMessage
        [DllImport("kernel32.dll")]
        public static extern uint FormatMessageW(uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId, out IntPtr lpBuffer, uint nSize, IntPtr Arguments);
    }

    public static class Shininject
    {

        private static bool IsAssemblyLoaded(string name)
        {
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (asm.GetName().Name == name)
                {
                    return true;
                }
            }

            return false;
        }

        private static byte[] StringToUtf16Le(string str)
        {
            var buffer = new byte[System.Text.Encoding.Unicode.GetByteCount(str)];
            System.Text.Encoding.Unicode.GetBytes(str, 0, str.Length, buffer, 0);
            return buffer;
        }

        private static bool FindPatternInMemoryRegion(MemoryBasicInformation region, byte[] pattern)
        {
            for (var i = 0; i < region.RegionSize.ToInt64() - pattern.Length; i++)
            {
                for (var j = 0; j < pattern.Length; j++)
                {
                    var b = Marshal.ReadByte(region.BaseAddress + i + j);
                    if (b != pattern[j])
                    {
                        break;
                    }

                    if (j == pattern.Length - 1)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static IEnumerable<MemoryBasicInformation> FindMemoryRegions(byte[] pattern)
        {
            var process = Process.GetCurrentProcess();
            var hProcess = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_READ, false, process.Id);

            try
            {
                var offset = IntPtr.Zero;
                uint memoryInfoSize = (uint)Marshal.SizeOf(typeof(MemoryBasicInformation));
                var memoryRegions = new List<MemoryBasicInformation>();
                while (true)
                {
                    var queryResult = Win32.VirtualQueryEx(hProcess, offset, out MemoryBasicInformation memory, memoryInfoSize);
                    if (queryResult == 0)
                    {
                        break;
                    }

                    memoryRegions.Add(memory);
                    offset = new IntPtr(offset.ToInt64() + memory.RegionSize.ToInt64());
                }

                foreach (var region in memoryRegions)
                {
                    if (region.State != Win32.MEM_COMMIT)
                    {
                        continue;
                    }

                    if ((region.Protect & Win32.PAGE_NOACCESS) != 0 || (region.Protect & Win32.PAGE_GUARD) != 0)
                    {
                        continue;
                    }

                    if (FindPatternInMemoryRegion(region, pattern))
                    {
                        yield return region;
                    }
                }
            }
            finally
            {
                Win32.CloseHandle(hProcess);
            }
        }

        private static string DumpMemoryRegion(MemoryBasicInformation region, string path)
        {
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                var offset = region.BaseAddress;
                var end = region.BaseAddress.ToInt64() + region.RegionSize.ToInt64();
                while (offset.ToInt64() < end)
                {
                    stream.WriteByte(Marshal.ReadByte(offset));
                    offset = new IntPtr(offset.ToInt64() + 1);
                }
            }
            return path;
        }

        private static void DumpAllMemoryRegions(string basePath)
        {
            foreach (var region in FindMemoryRegions(new byte[] { 0x4D, 0x5A }))
            {
                var baseAddress = region.BaseAddress.ToInt64();
                var size = region.RegionSize.ToInt64();
                Console.WriteLine($"Memory region found at {baseAddress:X} - {baseAddress + size:X}: {size} bytes");
                var file = DumpMemoryRegion(region, Path.ChangeExtension(Path.Combine(basePath, $"{baseAddress:X}"), ".bin"));
                Console.WriteLine($"Memory region dumped to {file}");
            }
        }

        public static void Inject()
        {
            var basePath = Path.GetTempFileName();
            File.Delete(basePath);
            Directory.CreateDirectory(basePath);

            Console.WriteLine("Dumping memory regions to " + basePath);
            DumpAllMemoryRegions(basePath);
        }
    }
}