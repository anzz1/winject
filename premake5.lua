workspace "winject"
   configurations { "Release" }
   platforms { "Win32", "x64" }
   location "build"
   objdir ("build/obj")
   buildlog ("build/log/%{prj.name}.log")

   characterset ("MBCS")
   staticruntime "Off"
   exceptionhandling "Off"
   floatingpoint "Fast"
   intrinsics "On"
   rtti "Off"
   flags { "NoBufferSecurityCheck", "NoIncrementalLink", "NoManifest", "NoPCH", "NoRuntimeChecks", "OmitDefaultLibrary" }
   buildoptions { "/kernel" }
   linkoptions { "/NODEFAULTLIB", "/SAFESEH:NO", "/EMITPOGOPHASEINFO", "/RELEASE", "/DEBUG:NONE" }

   filter "configurations:Release"
      runtime "Release"
      defines "NDEBUG"
      optimize "Speed"
      symbols "Off"

   filter "platforms:Win32"
      architecture "x86"

   filter "platforms:x64"
      architecture "x64"

project "ntdll_lib_stub"
   kind "SharedLib"
   language "C"
   targetname "ntdll"
   targetextension ".dll"
   targetdir "build/obj"
   files { "src/ntdll_lib_stub.c" }
   files { "src/ntdll.def" }
   entrypoint "DllMain"

project "winject"
   kind "ConsoleApp"
   language "C"
   targetextension ".exe"
   targetdir "bin"
   files { "src/winject.c" }
   entrypoint "main"
   dependson { "ntdll_lib_stub" }
   filter "platforms:Win32"
      targetname "winject32"
   filter "platforms:x64"
      targetname "winject64"
