REM @echo off
REM REM comments preferred: http://stackoverflow.com/a/12407934
REM ~ t-mattmc@microsoft.com 2016-06-14

SET POIROT_ROOT=@POIROT_ROOT@
SET model_name=vProgram
SET clean_name=progClean

if exist *.exe del *.exe
if exist *.pdb del *.pdb
if exist *.bpl del *.bpl
if exist corral_out_trace.txt del corral_out_trace.txt

copy %POIROT_ROOT%\poirot4.net\library\poirot_stubs.bpl

dotnet restore
dotnet build
rmdir /S /Q pub
dotnet publish -o pub
REM CCI doesn't know how to search this subdirectory structure, so copy the
REM versions of DLLs we want into the same directory.  Better ideas?
REM Note: DLLs in "native" subdirectories appear to contain native code, not
REM MSIL, so they are irrelevant to us.
copy pub\runtimes\win\lib\netstandard1.3\*.dll pub

REM TODO: Decide where the modified BCT should live.
call %POIROT_ROOT%\BCT-matt\BytecodeTranslator.exe /e:1 /ib /whole /heap:splitFields /libpaths "@DOTNET_CORE_LIBPATH@" pub\vProgram.dll pub\SVAuth.dll pub\SVX_Common.dll
REM TODO: Move PoirotMain back out of the namespace? ~ t-mattmc@microsoft.com 2016-06-15
call %POIROT_ROOT%\Corral\BctCleanup.exe %model_name%.bpl %clean_name%.bpl /main:SVAuth.VProgram.PoirotMain.Main /include:poirot_stubs.bpl
call %POIROT_ROOT%\Corral\corral.exe %clean_name%.bpl /printDataValues:1 /recursionBound:2 /k:1 /main:SVAuth.VProgram.PoirotMain.Main /tryCTrace /include:poirot_stubs.bpl

REM TODO: We want this for interactive use only.  Figure out how to conditionalize it.
if exist corral_out_trace.txt %POIROT_ROOT%\ConcurrencyExplorer.exe corral_out_trace.txt

:end
