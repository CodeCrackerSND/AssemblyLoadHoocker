/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 1/22/2016
 * Time: 2:00 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.IO;
using System.Windows.Forms;
using System.Reflection;

namespace AssemblyLoadHoocker
{
	/// <summary>
	/// Class with program entry point.
	/// </summary>
	internal sealed class Program
	{
		/// <summary>
		/// Program entry point.
		/// </summary>
		[STAThread]
		private static void Main(string[] args)
		{
		LoadHooking.Hoock();  // hoock Assembly.Load
			
		string filename = "D:\\Dotnet-Shield.exe";  // to be changed to your own file name
		byte[] filebytes = File.ReadAllBytes(filename);
		Assembly asm = Assembly.Load(filebytes);
		asm.EntryPoint.Invoke(null, new object[]{new string[]{""}});
		
		}
		
	}
}
