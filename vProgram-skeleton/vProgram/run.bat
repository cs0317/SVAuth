::@echo off

SET file_name=bin\Debug\netcoreapp1.0\vProgram
SET model_name=vProgram
SET clean_name=progClean

::C:
::cd %my_dir%

if exist *.exe del *.exe
if exist *.pdb del *.pdb
if exist *.bpl del *.bpl
if exist corral_out_trace.txt del corral_out_trace.txt

copy %POIROT_ROOT%\poirot4.net\library\poirot_stubs.bpl

dotnet restore
dotnet build

call %POIROT_ROOT%\Poirot4.NET\BCT\BytecodeTranslator.exe /e:1 /ib /whole /heap:splitFields %file_name%.dll ..\SVAuth\SVAuth.dll
call %POIROT_ROOT%\Corral\BctCleanup.exe %model_name%.bpl %clean_name%.bpl /main:PoirotMain.Main /include:poirot_stubs.bpl
call %POIROT_ROOT%\Corral\corral.exe %clean_name%.bpl /recursionBound:2 /k:1 /main:PoirotMain.Main /tryCTrace /include:poirot_stubs.bpl

::if exist corral_out_trace.txt %POIROT_ROOT%\ConcurrencyExplorer.exe corral_out_trace.txt
::


:end
