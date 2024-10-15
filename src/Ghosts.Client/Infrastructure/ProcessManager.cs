// Copyright 2017 Carnegie Mellon University. All Rights Reserved. See LICENSE.md file for terms.

using Ghosts.Domain;
using NLog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using Ghosts.Domain.Code.Helpers;
using System.Runtime.InteropServices;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Threading;
namespace Ghosts.Client.Infrastructure;

public static class ProcessManager
{
    private static readonly Logger _log = LogManager.GetCurrentClassLogger();

    public static int GetThisProcessPid()
    {
        var currentProcess = Process.GetCurrentProcess();
        return currentProcess.Id;
    }

    public static void KillProcessAndChildrenByHandler(TimelineHandler handler)
    {
        _log.Trace($"Killing: {handler.HandlerType}...");
        switch (handler.HandlerType)
        {
            case HandlerType.BrowserChrome:
                KillProcessAndChildrenByName("chrome");
                KillProcessAndChildrenByName("chromedriver");
                break;
            case HandlerType.BrowserFirefox:
                KillProcessAndChildrenByName("firefox");
                KillProcessAndChildrenByName("geckodriver");
                break;
            case HandlerType.Command:
                KillProcessAndChildrenByName("cmd");
                break;
            case HandlerType.PowerShell:
                KillProcessAndChildrenByName("powershell");
                break;
            case HandlerType.Word:
                KillProcessAndChildrenByName("winword");
                break;
            case HandlerType.Excel:
                KillProcessAndChildrenByName("excel");
                break;
            case HandlerType.PowerPoint:
                KillProcessAndChildrenByName("powerpnt");
                break;
            case HandlerType.Outlook:
                KillProcessAndChildrenByName("outlook");
                break;

        }
    }

    public static void KillProcessAndChildrenByName(string procName)
    {
        if (!Program.Configuration.ResourceControl.ManageProcesses) return;
        try
        {
            var processes = Process.GetProcessesByName(procName).ToList();
            processes.Sort((x1, x2) => x1.StartTime.CompareTo(x2.StartTime));

            var thisPid = GetThisProcessPid();

            foreach (var process in processes)
            {
                try
                {
                    if (process.Id == thisPid) //don't kill thyself
                        continue;

                    process.SafeKill();
                }
                catch (Exception e)
                {
                    _log.Trace($"Closing {procName} threw exception - {e}");
                }
            }
        }
        catch (Exception e)
        {
            _log.Trace($"Could not get processes by name? {procName} : {e}");
        }
    }

    public static void KillProcessAndChildrenByPid(int pid)
    {
        if (!Program.Configuration.ResourceControl.ManageProcesses) return;
        try
        {

            if (pid == 0) // Cannot close 'system idle process'.
                return;

            if (pid == GetThisProcessPid()) //don't kill thyself
                return;

            var searcher = new ManagementObjectSearcher($"Select * From Win32_Process Where ParentProcessID={pid}");
            var moc = searcher.Get();
            foreach (var mo in moc)
            {
                KillProcessAndChildrenByPid(Convert.ToInt32(mo["ProcessID"]));
            }
            try
            {
                var proc = Process.GetProcessById(pid);
                proc.SafeKill();
            }
            catch (Exception e)
            {
                _log.Trace(e);
            }
        }
        catch (Exception e)
        {
            _log.Trace(e);
        }
    }

    public static IEnumerable<int> GetPids(string processName)
    {
        try
        {
            var processes = Process.GetProcessesByName(processName);

            return processes.Select(proc => proc.Id).ToArray();
        }
        catch (Exception e)
        {
            _log.Trace(e);
            return new List<int>();
        }
    }

    public static class ProcessNames
    {
        public static string Chrome => "chrome";
        public static string ChromeDriver => "chromedriver";

        public static string Command => "cmd";
        public static string PowerShell => "powershell";

        public static string Firefox => "firefox";
        public static string GeckoDriver => "geckodriver";

        public static string Excel => "EXCEL";
        public static string Outlook => "OUTLOOK";
        public static string PowerPoint => "POWERPNT";
        public static string Word => "WINWORD";

        public static string WindowsFault => "werfault";
        public static string WindowsFaultSecure => "werfaultsecure";
    }

    public class ProcessResult
    {
        public string Output { get; set; }
        public Process Process { get; set; }
    }

    internal class SpoofPPID
    {
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll")]
        public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
        [DllImport("kernel32.dll")]
        public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        public enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        public static class CreationFlags
        {
            public const uint SUSPENDED = 0x4;
            public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            public const uint CREATE_NO_WINDOW = 0x08000000;
            public const int CREATE_NEW_CONSOLE = 0x00000010;

        }

        public const int STARTF_USESTDHANDLES = 0x00000100;
        public static readonly UInt32 MEM_COMMIT = 0x1000;
        public static readonly UInt32 MEM_RESERVE = 0x2000;
        public static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
        public static readonly UInt32 PAGE_READWRITE = 0x04;

        public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        public const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
        public const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;

        public const int SW_HIDE = 0;
        public const int SW_SHOW = 5;

        public static int GetParentProcessId(string processName)
        {
            // Find the process by the specified name
            int pid = 0;
            processName = Path.GetFileNameWithoutExtension(processName);
            //int session = Process.GetCurrentProcess().SessionId;
            string User = Process.GetCurrentProcess().StartInfo.UserName;
            Process[] allprocess = Process.GetProcessesByName(processName);

            try
            {
                if (pid == 0)
                {
                    foreach (Process proc in allprocess)
                    {
                        if (proc.StartInfo.UserName == User)
                        {
                            _log.Debug($"Found {processName} pid: {proc.Id}");
                            pid = proc.Id;
                            break;
                        }

                    }
                }
                else
                {
                    int currentProcessId = Process.GetCurrentProcess().Id;
                    _log.Debug($"Failed to find {processName}");
                    _log.Debug($"Using current process pid: {currentProcessId}");
                    pid = currentProcessId;
                }

            }
            catch (Exception ex)
            {
                _log.Error($"Failed to find parent ID specified: {Marshal.GetExceptionCode()}");
                _log.Error(ex.ToString());
            }
            return pid;

        }

        public static Process GetParentProcess(int processId)
        {
            try
            {
                // Use WMI to query the Win32_Process class for the specific process ID
                string query = $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject mo in results)
                    {
                        // Get the parent process ID
                        int parentProcessId = Convert.ToInt32(mo["ParentProcessId"]);
                        return Process.GetProcessById(parentProcessId);
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Error($"Error retrieving parent process: {ex.Message}");
            }
            return null; // If no parent process is found
        }
    }

    public static ProcessResult CreateProcess(string processName, string command, string parentProcess = null, bool GetOutPut = true)
    {
        var result = new ProcessResult();
        result.Output = "";

        IntPtr hReadPipe = IntPtr.Zero, hWritePipe = IntPtr.Zero;
        SpoofPPID.SECURITY_ATTRIBUTES securityAttributes = new SpoofPPID.SECURITY_ATTRIBUTES();
        securityAttributes.nLength = Marshal.SizeOf(securityAttributes);
        securityAttributes.bInheritHandle = true; // Allow handle inheritance
                                                  // Attempt to create the pipe
        if (SpoofPPID.CreatePipe(out hReadPipe, out hWritePipe, ref securityAttributes, 0) == IntPtr.Zero || hReadPipe == IntPtr.Zero || hWritePipe == IntPtr.Zero)
        {
            _log.Error("Failed to create pipes for process output redirection.");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        SpoofPPID.SetHandleInformation(hReadPipe, (uint)SpoofPPID.HANDLE_FLAGS.INHERIT, 0);
        SpoofPPID.SetHandleInformation(hWritePipe, (uint)SpoofPPID.HANDLE_FLAGS.INHERIT, (uint)SpoofPPID.HANDLE_FLAGS.INHERIT);

        var sInfoEx = new SpoofPPID.STARTUPINFOEX();
        sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
        sInfoEx.StartupInfo.hStdOutput = hWritePipe;
        sInfoEx.StartupInfo.hStdError = hWritePipe;  // Redirect standard error
        sInfoEx.StartupInfo.dwFlags = SpoofPPID.STARTF_USESTDHANDLES; // Use standard handles
        var pInfo = new SpoofPPID.PROCESS_INFORMATION();
        IntPtr lpValue = IntPtr.Zero;

        SpoofPPID.STARTUPINFOEX siex = new SpoofPPID.STARTUPINFOEX();

        bool processCreated = false; // Flag to indicate if the process was created successfully
        string lpCommandLine = $"{processName} {command}";

        try
        {


            if (string.IsNullOrEmpty(parentProcess))
            {
                _log.Debug("No Parent Process specified, using current Process");
                _log.Trace($"Creating process with command: {lpCommandLine}");

                // Create the process
                processCreated = SpoofPPID.CreateProcess(null, lpCommandLine, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref sInfoEx, ref pInfo);
                if (Marshal.GetLastWin32Error() != 0)
                {
                    _log.Error($"Process creation failed with Error code: {Marshal.GetLastWin32Error()}");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

            }
            else
            {
                int PPID = SpoofPPID.GetParentProcessId(parentProcess);
                if (PPID != -1)
                {


                    IntPtr procHandle = SpoofPPID.OpenProcess(SpoofPPID.ProcessAccessFlags.CreateProcess, false, PPID);
                    IntPtr lpSize = IntPtr.Zero;
                    SpoofPPID.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);

                    siex.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    SpoofPPID.InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, ref lpSize); 
                    IntPtr lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValueProc, procHandle);
                    SpoofPPID.UpdateProcThreadAttribute(siex.lpAttributeList, 0, (IntPtr)SpoofPPID.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                    processCreated = SpoofPPID.CreateProcess(null, lpCommandLine, IntPtr.Zero, IntPtr.Zero, false, SpoofPPID.CreationFlags.SUSPENDED | SpoofPPID.CreationFlags.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref siex, ref pInfo);
                    _log.Debug("Process Created. Process ID: {0}", pInfo.dwProcessId);

                    IntPtr ThreadHandle = pInfo.hThread;
                    SpoofPPID.ResumeThread(ThreadHandle);
                    _log.Debug($"Resuming Thread {ThreadHandle} of Process ID: {pInfo.dwProcessId}");


                }
            }

            // Check if process was created successfully
            if (!processCreated)
            {
                _log.Error("CreateProcess failed with error code: " + Marshal.GetLastWin32Error());
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }


            // Check what process is parent of spawned process
            //if (SpoofPPID.GetParentProcess(Process.GetCurrentProcess().Id) != SpoofPPID.GetParentProcess(pInfo.dwProcessId))
            //{
            //    pInfo.dwProcessId = pi.dwProcessId;
            //}

            _log.Debug($"Created process with PID: {pInfo.dwProcessId}");
            SpoofPPID.CloseHandle(hWritePipe);

            //Log.Trace($"Getting output of process. ID: {pInfo.dwProcessId}");
            try
            {
                var proc = Process.GetProcessById(pInfo.dwProcessId);
                result.Process = proc;
                if (GetOutPut)
                {
                    if (!proc.HasExited)
                    {
                        //Log.Trace("Waiting for Exit");
                        proc.WaitForExit();
                        //Log.Trace("Process Complete!");
                    }
                    else
                    {
                        //Log.Warn("The process has already exited before WaitForExit was called.");
                    }

                    Thread.Sleep(1000);

                    string output;
                    using (var outputStream = new FileStream(new SafeFileHandle(hReadPipe, false), FileAccess.Read, 4096, false))
                    using (var reader = new StreamReader(outputStream))
                    {
                        // Read the output until the stream ends
                        output = reader.ReadToEnd();
                    }
                    // Log the output for debugging
                    if (output == "") { output = "Process was spawned with a different parent"; }
                    _log.Debug($"Process output: {output}");
                    //return output; // Return the captured output
                    result.Output = output;
                }
                
            }
            catch (ArgumentException)
            {
                _log.Error($"Process with ID {pInfo.dwProcessId} is not running.");
            }
            catch (Exception ex)
            {
                _log.Error($"Unexpected error while handling the process: {ex.Message}");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return result;
        }
        finally
        {
            // Free the attribute list
            if (sInfoEx.lpAttributeList != IntPtr.Zero)
            {
                SpoofPPID.DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
            }
            Marshal.FreeHGlobal(lpValue);

            // Close process and thread handles
            if (pInfo.hProcess != IntPtr.Zero)
            {
                SpoofPPID.CloseHandle(pInfo.hProcess);
            }
            if (pInfo.hThread != IntPtr.Zero)
            {
                SpoofPPID.CloseHandle(pInfo.hThread);
            }
            if (hReadPipe != IntPtr.Zero)
            {
                SpoofPPID.CloseHandle(hReadPipe);
            }
            if (hWritePipe != IntPtr.Zero)
            {
                SpoofPPID.CloseHandle(hWritePipe);
            }
        }
    }

}