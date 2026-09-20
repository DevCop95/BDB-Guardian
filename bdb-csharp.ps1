$csharp = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

public static class BdbHandleScan {
    const int SystemHandleInformation = 16;
    const uint PROCESS_DUP_HANDLE = 0x0040;
    const uint DUPLICATE_SAME_ACCESS = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_HANDLE {
        public uint ProcessId;
        public byte ObjectTypeNumber;
        public byte Flags;
        public ushort Handle;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    // RmGetList writes RM_PROCESS_INFO (~668 bytes/entry), NOT RM_UNIQUE_PROCESS.
    // Using the small struct here was THE heap-corruption bug (native entries
    // blasted past 12-byte slots). Every reference implementation
    // (MSDN, Roslyn FileLockCheck, ironman) uses RM_PROCESS_INFO. Fixed.
    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS {
        public uint dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, ref int retLen);
    [DllImport("ntdll.dll")]
    static extern int NtQueryObject(IntPtr h, int cls, IntPtr buf, int len, ref int retLen);
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc,
        out IntPtr dst, uint access, bool inherit, uint opts);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern uint GetFileType(IntPtr hFile);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern uint QueryDosDevice(string dev, StringBuilder buf, uint bufsz);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint handle, int flags, string key);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint handle);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint handle, uint nFiles, string[] files,
        uint nApps, IntPtr apps, uint nServices, string[] services);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint handle, out uint needed, ref uint count,
        [In, Out] RM_PROCESS_INFO[] procs, ref uint reboot);

    public static string GetDevicePath(string drive) {
        var sb = new StringBuilder(512);
        uint r = QueryDosDevice(drive, sb, (uint)sb.Capacity);
        return r == 0 ? null : sb.ToString();
    }

    static string ReadUniString(IntPtr buf) {
        try {
            short len = Marshal.ReadInt16(buf);
            if (len <= 0 || len > 2048) return null; // bounds-check: never trust kernel strings blindly
            IntPtr strPtr = Marshal.ReadIntPtr(buf, 8);
            if (strPtr == IntPtr.Zero) return null;
            return Marshal.PtrToStringUni(strPtr, len / 2);
        } catch { return null; }
    }

    public static int TotalPids = 0;
    public static int ScannedPids = 0;

    // Who has a file open? (Restart Manager: fast and exact)
    // Correct RM_PROCESS_INFO marshaling + retry loop (Roslyn pattern).
    public static string[] RmWhoHas(string filePath) {
        var res = new List<string>();
        uint sess;
        if (RmStartSession(out sess, 0, Guid.NewGuid().ToString()) != 0) return res.ToArray();
        try {
            if (RmRegisterResources(sess, 1, new string[] { filePath }, 0, IntPtr.Zero, 0, null) != 0)
                return res.ToArray();
            uint count = 0, reboot = 0;
            RM_PROCESS_INFO[] arr = null;
            for (int retry = 0; retry < 6; retry++) {
                uint needed = 0;
                int rc = RmGetList(sess, out needed, ref count, arr, ref reboot);
                if (rc == 0) {
                    if (arr != null) {
                        for (uint i = 0; i < count && i < (uint)arr.Length; i++)
                            res.Add(arr[i].Process.dwProcessId.ToString());
                    }
                    break;
                }
                if (rc != 234 || needed == 0 || needed > 1024) break;
                count = needed;
                arr = new RM_PROCESS_INFO[needed];
            }
        } finally { RmEndSession(sess); }
        return res.ToArray();
    }

    static void ScanOnePid(uint pid, List<SYSTEM_HANDLE> handles, IntPtr self,
            string volumeDevice, List<string> res, object lk,
            Dictionary<byte, string> typeCache, DateTime t0, int maxSeconds) {
        IntPtr proc = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
        if (proc == IntPtr.Zero) return;
        IntPtr tmp = Marshal.AllocHGlobal(0x1000);
        try {
            foreach (SYSTEM_HANDLE h in handles) {
                if ((DateTime.UtcNow - t0).TotalSeconds > maxSeconds) break;
                string tname = null;
                bool cached = false;
                lock (typeCache) { cached = typeCache.TryGetValue(h.ObjectTypeNumber, out tname); }
                if (!cached) {
                    // Resolve WITHOUT the lock: a stuck NtQueryObject must not stall the rest
                    string resolved = null;
                    IntPtr d0;
                    if (DuplicateHandle(proc, new IntPtr(h.Handle), self, out d0, 0, false, DUPLICATE_SAME_ACCESS)) {
                        int rl0 = 0;
                        if (NtQueryObject(d0, 2, tmp, 0x1000, ref rl0) == 0)
                            resolved = ReadUniString(tmp);
                        CloseHandle(d0);
                    }
                    lock (typeCache) {
                        if (!typeCache.TryGetValue(h.ObjectTypeNumber, out tname))
                            typeCache[h.ObjectTypeNumber] = tname = resolved;
                    }
                }
                if (tname != "File") continue;
                IntPtr dup;
                if (!DuplicateHandle(proc, new IntPtr(h.Handle), self, out dup, 0, false, DUPLICATE_SAME_ACCESS))
                    continue;
                // Pipes hang name queries: only resolve real disk files/volumes.
                uint ftype = GetFileType(dup);
                if (ftype != 1 && ftype != 0x8001) { CloseHandle(dup); continue; }
                int rl = 0;
                string name = (NtQueryObject(dup, 1, tmp, 0x1000, ref rl) == 0) ? ReadUniString(tmp) : null;
                CloseHandle(dup);
                if (String.IsNullOrEmpty(name)) continue;
                bool keep = name.EndsWith("\\MRT.exe", StringComparison.OrdinalIgnoreCase)
                    || String.Equals(name.TrimEnd('\\'), volumeDevice, StringComparison.OrdinalIgnoreCase)
                    || name.IndexOf("Microsoft\\Windows Defender", StringComparison.OrdinalIgnoreCase) >= 0;
                if (keep) {
                    lock (lk) { res.Add(pid + "|" + h.Handle + "|" + name); }
                }
            }
        } finally {
            Marshal.FreeHGlobal(tmp);
            CloseHandle(proc);
        }
    }

    // Parallel scan of File handles looking for volume/defender (time-boxed).
    // Returns lines "pid|handle|name".
    public static string[] ScanVolumeHandles(int maxSeconds, string volumeDevice) {
        var res = new List<string>();
        object lk = new object();
        var typeCache = new Dictionary<byte, string>();
        TotalPids = 0; ScannedPids = 0;
        var t0 = DateTime.UtcNow;

        int size = 0x20000;
        IntPtr buf = Marshal.AllocHGlobal(size);
        var groups = new Dictionary<uint, List<SYSTEM_HANDLE>>();
        try {
            int retLen = 0;
            int st = NtQuerySystemInformation(SystemHandleInformation, buf, size, ref retLen);
            while (st == unchecked((int)0xC0000004)) {
                Marshal.FreeHGlobal(buf);
                size *= 2;
                buf = Marshal.AllocHGlobal(size);
                st = NtQuerySystemInformation(SystemHandleInformation, buf, size, ref retLen);
            }
            if (st != 0) return res.ToArray();
            uint count = (uint)Marshal.ReadInt32(buf);
            int entrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE));
            long base_ = buf.ToInt64() + 8;
            for (uint i = 0; i < count; i++) {
                IntPtr e = new IntPtr(base_ + (long)i * entrySize);
                SYSTEM_HANDLE h = (SYSTEM_HANDLE)Marshal.PtrToStructure(e, typeof(SYSTEM_HANDLE));
                if (h.ProcessId == 0) continue;
                List<SYSTEM_HANDLE> lst;
                if (!groups.TryGetValue(h.ProcessId, out lst)) {
                    lst = new List<SYSTEM_HANDLE>();
                    groups[h.ProcessId] = lst;
                }
                lst.Add(h);
            }
        } finally { Marshal.FreeHGlobal(buf); }

        var pids = new List<uint>(groups.Keys);
        pids.Sort((a, b) => b.CompareTo(a)); // high PIDs (new processes) first
        TotalPids = pids.Count;
        IntPtr self = GetCurrentProcess();

        Parallel.ForEach(pids, new ParallelOptions { MaxDegreeOfParallelism = 64 },
        (pid) => {
            if ((DateTime.UtcNow - t0).TotalSeconds > maxSeconds) return;
            try {
                // Each PID in a child task with timeout: if one NtQueryObject hangs
                // on a weird handle, that PID is abandoned and the scan continues.
                var t = Task.Factory.StartNew(() =>
                    ScanOnePid(pid, groups[pid], self, volumeDevice, res, lk, typeCache, t0, maxSeconds));
                t.Wait(2500);
            } catch { }
            lock (lk) {
                ScannedPids++;
                if (ScannedPids % 50 == 0) Console.WriteLine("  [scan] {0}/{1} PIDs...", ScannedPids, TotalPids);
            }
        });
        return res.ToArray();
    }
}
"@
Add-Type -TypeDefinition $csharp -ErrorAction Stop
