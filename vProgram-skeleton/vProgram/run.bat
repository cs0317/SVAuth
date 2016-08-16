REM @echo off
REM REM comments preferred: http://stackoverflow.com/a/12407934
REM ~ t-mattmc@microsoft.com 2016-06-14

SET SVAUTH_ROOT=@SVAUTH_PATH@
SET model_name=vProgram
SET clean_name=progClean

if exist *.exe del *.exe
if exist *.pdb del *.pdb
if exist *.bpl del *.bpl
if exist corral_out_trace.txt del corral_out_trace.txt

dotnet restore
dotnet build
rmdir /S /Q pub
dotnet publish -o pub
REM CCI doesn't know how to search this subdirectory structure, so copy the
REM versions of DLLs we want into the same directory.  Better ideas?
REM Note: DLLs in "native" subdirectories appear to contain native code, not
REM MSIL, so they are irrelevant to us.
copy pub\runtimes\win\lib\netstandard1.3\*.dll pub

REM With /e:1, BCT wasn't checking for an exception at the call site of SignInRP.
REM I haven't investigated why yet. ~ t-mattmc@microsoft.com 2016-07-15
call %SVAUTH_ROOT%\bytecodetranslator\Binaries\BytecodeTranslator.exe /e:2 /ib /whole /heap:splitFields /libpaths "@DOTNET_CORE_LIBPATH@" pub\vProgram.dll pub\SVAuth.dll pub\SVX.dll
call %SVAUTH_ROOT%\bytecodetranslator\corral\bin\Debug\BctCleanup.exe %model_name%.bpl %clean_name%.bpl /main:Program.Main /include:%SVAUTH_ROOT%\bytecodetranslator\collection_stubs.bpl /include:%SVAUTH_ROOT%\svx_stubs.bpl
call %SVAUTH_ROOT%\bytecodetranslator\corral\bin\Debug\corral.exe %clean_name%.bpl /printDataValues:1 /recursionBound:10 /k:1 /main:Program.Main /tryCTrace /trackAllVars

REM TODO: We want this for interactive use only.  Figure out how to conditionalize it.
REM ConcurrencyExplorer is an optional manual installation until we decide
REM whether and how to bundle it. ~ t-mattmc@microsoft.com 2016-07-21
if exist %SVAUTH_ROOT%\ConcurrencyExplorer.exe if exist corral_out_trace.txt %SVAUTH_ROOT%\ConcurrencyExplorer.exe corral_out_trace.txt

:end
