# SVAuth: Self-verifying single-sign-on solutions

This is an effort by
[Matt McCutchen](mailto:%22Matt%20McCutchen%22%20%3Ct-mattmc@microsoft.com%3E)
and [Shuo Chen](http://research.microsoft.com/en-us/people/shuochen/) to build a
relying party framework that aims to accommodate all major web-based single
sign-on (SSO) solutions. SVAuth is designed to be platform independent -- it
works with PHP, ASP.NET, Python, etc. The framework enables "self-verifying
execution" (SVX). An earlier version of SVX, called "Certification of Symbolic
Transactions", was described in
[this paper](http://research.microsoft.com/apps/pubs/default.aspx?id=241150).   

This codebase is not yet ready for others to use. Please contact us if you'd
like more information.

## Status notes

* Facebook SSO works.
* Verification passes, but we think it's more likely that the code contains
  contradictory `assume`s than that it is actually correct!

## Building and running

Currently we only test SVAuth on Windows. (Since the SVAuth agent is based on
.NET Core, once we have the certification server working again, it should be
easy to run the agent on any platform supported by .NET Core using a remote
certification server running on Windows. Making the certification server cross-
platform would be much more work, and we may or may not ever do it.)

1. Make sure you have the submodules: if you did not use
   `git clone --recursive`, then run `git submodule update --init --recursive`
   now.
2. Install [.NET Core](https://www.microsoft.com/net/core).
3. Open and build `SVAuth.sln` with Visual Studio.
4. Place a copy of the [Z3 prover](https://github.com/Z3Prover/z3/), `z3.exe`,
   in `bytecodetranslator\corral\bin\Debug`.
5. Optional but highly recommended: Place a copy of the
   [CHESS](https://chesstool.codeplex.com/) Concurrency Explorer,
   `ConcurrencyExplorer.exe`, in the same directory as this readme.
6. Make sure IIS is installed.
7. Make sure IIS has read permission on the `SVAuth` subdirectory, and run
   `SVAuth\IIS_setup.cmd` as administrator to add it to IIS as a virtual
   directory.
8. If you want to test the PHP adapter, install "PHP 7.0.7 (x86)" using the
   [Microsoft Web Platform Installer](https://www.microsoft.com/web/downloads/platform.aspx)
   and ensure that this PHP version is enabled on the `SVAuth` virtual
   directory. One convenient way to do this is using
   [PHP Manager](https://phpmanager.codeplex.com/).
9. Run the SVAuth project with Visual Studio. The example ASP.NET relying party
   application will open in your default web browser.

Note: `SVAuth.sln` contains dependency edges from `SVX` to the relevant BCT and
Corral tools to ensure they are up to date before SVAuth runs. These cannot be
added directly to `SVX` as references because `SVX` targets .NET Core and the
BCT and Corral projects target .NET Framework.

## Earlier repositories (discontinued)

* [AuthPlatelet](https://github.com/AuthPlatelet/AuthPlatelet)
* [AuthJS] (https://github.com/cs0317/AuthClassLib)
