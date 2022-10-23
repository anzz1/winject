workspace "winject"
   configurations { "Release" }
   platforms { "Win32", "Win64" }
   location "build"
   objdir ("build/obj")
   buildlog ("build/log/%{prj.name}.log")

   characterset ("MBCS")
   staticruntime "Off"
   omitframepointer "On"
   flags { "NoBufferSecurityCheck", "NoIncrementalLink", "NoManifest", "NoPCH", "NoRuntimeChecks", "OmitDefaultLibrary" }

   filter "configurations:Release"
      defines "NDEBUG"
      optimize "Speed"
      symbols "Off"

   filter "platforms:Win32"
      architecture "x32"
	  libdirs { "build/lib/x86" }

   filter "platforms:Win64"
      architecture "x64"
	  libdirs { "build/lib/x64" }

project "ntdll_lib_stub"
   kind "SharedLib"
   language "C"
   targetname "ntdll"
   targetextension ".dll"
   targetdir "build/obj"
   files { "src/ntdll_lib_stub.c" }
   files { "src/ntdll.def" }
   linkoptions { '/entry:"DllMain"' }

project "winject"
   kind "ConsoleApp"
   language "C"
   targetextension ".exe"
   targetdir "bin"
   files { "src/winject.c" }
   linkoptions { '/entry:"main"' }
   dependson { "ntdll_lib_stub" }
   filter "platforms:Win32"
      targetname "winject32"
   filter "platforms:Win64"
      targetname "winject64"
