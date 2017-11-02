/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 4/2/2015
 * Time: 11:49 AM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.IO;
using System.Reflection;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Collections;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnlib.IO;

namespace AssemblyLoadHoocker
{
	/// <summary>
	/// Description of DynamicMethodHoocking.
	/// </summary>
	public class LoadHooking
	{
		public LoadHooking()
		{
		}
		
    
	public static byte[] assembly_bytes;
	
	public static void DoReflection()
	{
		if (assembly_bytes==null||assembly_bytes.Length==0)
		return;
		
		AssemblyDef asm = AssemblyDef.Load(assembly_bytes);
		if (asm.ManifestModule.EntryPoint!=null)
		{
		Importer importer = new Importer(asm.ManifestModule);
		IMethod MessageBox_Show = importer.Import(typeof(System.Windows.Forms.MessageBox).GetMethod("Show",new Type[]{typeof(string)}));
		IList<Instruction> instrs = asm.ManifestModule.EntryPoint.Body.Instructions;
		instrs.Insert(0, new Instruction(OpCodes.Ldstr, "Injected Message!"));
		instrs.Insert(1, new Instruction(OpCodes.Call, MessageBox_Show));
		instrs.Insert(2, new Instruction(OpCodes.Pop));
		}

			
			using (MemoryStream ms = new MemoryStream())
    		{
			asm.Write(ms);
			assembly_bytes = ms.ToArray();
			}
				
	}
		
	internal static Assembly HoockerProc(byte[] asmbytes)
	{  // 1 parameter since Assembly.Load Method (Byte[]) is static
if (realoldbytes==null)
return null;

assembly_bytes = asmbytes;
DoReflection();
asmbytes = new byte[0];
int Length = 0;  // restore old code:
WriteProcessMemory(-1, patch_place, realoldbytes, realoldbytes.Length, ref Length);
Assembly asm = (Assembly)Assembly_Load_method.Invoke(null,new object[]{assembly_bytes});  // call original method



// hoock again:
WriteProcessMemory(-1, patch_place, jumpbytes, jumpbytes.Length, ref Length);




return asm;

	}
	
	
		public static byte[] UIntToByte(uint ivalue)
		{
		byte[] uintBytes = BitConverter.GetBytes(ivalue);
		return uintBytes;
		}
	
	[DllImport("kernel32", ExactSpelling=true, CharSet=CharSet.Ansi, SetLastError=true)]
	private static extern int WriteProcessMemory(int hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);
	
	[DllImport("kernel32.dll", SetLastError=true)]
	static extern IntPtr VirtualAlloc(IntPtr lpAddress,int dwSize,
	AllocationType flAllocationType, MemoryProtection flProtect);
	
  [Flags()]
  public enum AllocationType:uint
  {
    COMMIT=0x1000,
    RESERVE=0x2000,
    RESET=0x80000,
    LARGE_PAGES=0x20000000,
    PHYSICAL=0x400000,
    TOP_DOWN=0x100000,
    WRITE_WATCH=0x200000
  }

  [Flags()]
  public enum MemoryProtection:uint
  {
    EXECUTE=0x10,
    EXECUTE_READ=0x20,
    EXECUTE_READWRITE=0x40,
    EXECUTE_WRITECOPY=0x80,
    NOACCESS=0x01,
    READONLY=0x02,
    READWRITE=0x04,
    WRITECOPY=0x08,
    GUARD_Modifierflag=0x100,
    NOCACHE_Modifierflag = 0x200,
    WRITECOMBINE_Modifierflag = 0x400
  }
	
  public static void SaveRegisters(MemoryStream ms,IntPtr register_keeper)
  {
/*
00500000    A3 00005500     MOV DWORD PTR DS:[550000],EAX
00500005    890D 04005500   MOV DWORD PTR DS:[550004],ECX
0050000B    8915 08005500   MOV DWORD PTR DS:[550008],EDX
00500011    891D 0C005500   MOV DWORD PTR DS:[55000C],EBX
00500017    8925 10005500   MOV DWORD PTR DS:[550010],ESP
0050001D    892D 14005500   MOV DWORD PTR DS:[550014],EBP
00500023    8935 18005500   MOV DWORD PTR DS:[550018],ESI
00500029    893D 1C005500   MOV DWORD PTR DS:[55001C],EDI
*/
byte[] rbytes = BitConverter.GetBytes((uint)register_keeper);
ms.WriteByte(0xA3);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+1*4);
ms.WriteByte(0x89);
ms.WriteByte(0x0D);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+2*4);
ms.WriteByte(0x89);
ms.WriteByte(0x015);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+3*4);
ms.WriteByte(0x89);
ms.WriteByte(0x01D);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+4*4);
ms.WriteByte(0x89);
ms.WriteByte(0x025);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+5*4);
ms.WriteByte(0x89);
ms.WriteByte(0x02D);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+6*4);
ms.WriteByte(0x89);
ms.WriteByte(0x035);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+7*4);
ms.WriteByte(0x89);
ms.WriteByte(0x03D);
ms.Write(rbytes,0,rbytes.Length);


  }
	
    public static void RestoreRegisters(MemoryStream ms,IntPtr register_keeper)
  {
/*
00290034    A1 00002A00     MOV EAX,DWORD PTR DS:[2A0000]
00290039    8B0D 04002A00   MOV ECX,DWORD PTR DS:[2A0004]
0029003F    8B15 08002A00   MOV EDX,DWORD PTR DS:[2A0008]
00290045    8B1D 0C002A00   MOV EBX,DWORD PTR DS:[2A000C]
0029004B    8B25 10002A00   MOV ESP,DWORD PTR DS:[2A0010]
00290051    8B2D 14002A00   MOV EBP,DWORD PTR DS:[2A0014]
00290057    8B35 18002A00   MOV ESI,DWORD PTR DS:[2A0018]
0029005D    8B3D 1C002A00   MOV EDI,DWORD PTR DS:[2A001C]
*/
byte[] rbytes = BitConverter.GetBytes((uint)register_keeper);
// ms.WriteByte(0xA1); - DO NOT RESTORE EAX since it holds the return value!
// ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+1*4);
ms.WriteByte(0x8B);
ms.WriteByte(0x0D);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+2*4);
ms.WriteByte(0x8B);
ms.WriteByte(0x015);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+3*4);
ms.WriteByte(0x8B);
ms.WriteByte(0x01D);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+4*4);
ms.WriteByte(0x8B);
ms.WriteByte(0x025);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+5*4);
ms.WriteByte(0x8B);
ms.WriteByte(0x02D);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+6*4);
ms.WriteByte(0x8B);
ms.WriteByte(0x035);
ms.Write(rbytes,0,rbytes.Length);

rbytes = BitConverter.GetBytes((uint)register_keeper+7*4);
ms.WriteByte(0x8B);
ms.WriteByte(0x03D);
ms.Write(rbytes,0,rbytes.Length);


  }
  
    static MethodInfo Assembly_Load_method=null;
	public static void Hoock()
	{
	Assembly_Load_method = typeof(System.Reflection.Assembly).GetMethod("Load",new Type[]{typeof(byte[])});
	
	if (Assembly_Load_method==null) return;

	HoockerProc(new byte[0]);  // invoke method so it will be compiled!
	try
	{
		Assembly_Load_method.Invoke(null,new object[]{new byte[]{}});
	}
	catch
	{
	
	}
	assembly_bytes = File.ReadAllBytes(	Assembly.GetExecutingAssembly().Location);
	DoReflection();  // just to compile the craps
	
	IntPtr method_address = Assembly_Load_method.MethodHandle.GetFunctionPointer();
	// System.Windows.Forms.MessageBox.Show(method_address.ToString("X8"));
	MethodInfo new_method =  typeof(LoadHooking).GetMethod("HoockerProc", BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
	IntPtr new_method_address = new_method.MethodHandle.GetFunctionPointer();

realoldbytes = new byte[6];
Marshal.Copy(method_address, realoldbytes, 0, realoldbytes.Length);
if (realoldbytes[3]!=0x083&&realoldbytes[4]!=0x0EC && (realoldbytes[3]!=0x050&&realoldbytes[4]!=0x33&&realoldbytes[5]!=0xC0))  // if is not SUB ESP,48 and not PUSH EAX XOR EAX,EAX
{
realoldbytes = new byte[5];
Marshal.Copy(method_address, realoldbytes, 0, realoldbytes.Length);
}
/* First needs 6 bytes:
003B2260    55                   PUSH EBP
003B2261    8BEC                 MOV EBP,ESP
003B2263    83EC 48              SUB ESP,48
003B2266    894D FC              MOV DWORD PTR SS:[EBP-4],ECX
003B2269    8955 F8              MOV DWORD PTR SS:[EBP-8],EDX
003B226C    833D 3C6B2A00 00     CMP DWORD PTR DS:[2A6B3C],0
003B2273    74 05                JE SHORT 003B227A
Seconds needs 5 bytes:
004A2300    55              PUSH EBP
004A2301    8BEC            MOV EBP,ESP
004A2303    57              PUSH EDI
004A2304    56              PUSH ESI
004A2305    53              PUSH EBX
004A2306    50              PUSH EAX
004A2307    8BF1            MOV ESI,ECX
004A2309    8BDA            MOV EBX,EDX
004A230B    81C6 51020000   ADD ESI,251


*/

patch_place = method_address;
	
IntPtr adr_myhook = VirtualAlloc(IntPtr.Zero, 100, 
                    AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
IntPtr register_keeper = VirtualAlloc(IntPtr.Zero, 100, 
                    AllocationType.COMMIT, MemoryProtection.READWRITE);

MemoryStream ms = new MemoryStream();
SaveRegisters(ms,register_keeper);

int jumptomymethod = (int)new_method_address-(int)adr_myhook-(int)ms.Position-5;
byte[] rbytes = BitConverter.GetBytes(jumptomymethod);
ms.WriteByte(0xE8);  // call
ms.Write(rbytes,0,rbytes.Length);

RestoreRegisters(ms,register_keeper);

// This is the old NOT working code:
/* ms.Write(realoldbytes,0,realoldbytes.Length);
ms.WriteByte(0xB8);  // 002C0068    B8 00010400     MOV EAX,40100
rbytes = BitConverter.GetBytes((int)method_address+5);
ms.Write(rbytes,0,rbytes.Length);
ms.WriteByte(0xFF);  // 002C006D    FFE0            JMP EAX
ms.WriteByte(0xE0);  // 002C006D    FFE0            JMP EAX
*/
ms.WriteByte(0xC3);  // an simple return (RETN) so it will return the control to original method!

// finnaly create bytes and copy them to adr_myhook
byte[] myhook_bytes = ms.ToArray();
Marshal.Copy(myhook_bytes,0,adr_myhook,myhook_bytes.Length);

jumpbytes = new byte[5];
if (realoldbytes.Length==6)
{
jumpbytes = new byte[6];
jumpbytes[jumpbytes.Length-1]=0x90; // nop
}
// jump to my hoock: where to jump - from where - 5
int jumptomyhook = (int)adr_myhook-(int)method_address-5;
rbytes = BitConverter.GetBytes(jumptomyhook);

jumpbytes[0]=0xE9;  // E9 = jmp

	
for (int i=0;i<4;i++)
jumpbytes[i+1]=rbytes[i];

int Length=0;
WriteProcessMemory(-1, method_address, jumpbytes, jumpbytes.Length, ref Length);
	
	}

  	static IntPtr patch_place=IntPtr.Zero;
  	static byte[] realoldbytes;
  	static byte[] jumpbytes;
	
	}
}
