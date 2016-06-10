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

* Facebook SSO works if you comment out the SVX_Ops.Certify call.
* The vProgram for Facebook SSO has some missing pieces.
* SVX gets as far as calling Bytecode Translator but triggers an internal error
  in Bytecode Translator. We're not bothering to investigate the error until the
  vProgram stabilizes a bit.

## Earlier repositories (discontinued)

* [AuthPlatelet](https://github.com/AuthPlatelet/AuthPlatelet)
* [AuthJS] (https://github.com/cs0317/AuthClassLib)
