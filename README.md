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

## Earlier repositories (discontinued)

* [AuthPlatelet](https://github.com/AuthPlatelet/AuthPlatelet)
* [AuthJS] (https://github.com/cs0317/AuthClassLib)
