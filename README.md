# SVAuth: Self-verifying single-sign-on solutions

<img src="logo1.jpg" style="width: 200px;"/>
SVAuth tries to provide the simplest and the most secure integration solution for a website to integrate single-sign-on (SSO) services. It is so simple that a website programmer doesn't need to know anything about SSO protocols or implementations. It is secure because every user login is formally proved for the correctness of its core logic by the state-of-the-art program verifier. 

If your website needs SSO login, don't be overwhelmed by all kinds of libraries and protocol documents. Try SVAuth. It may save you tons of time and effort, and save your website from several types of security bugs!

## Goal and status

**Goal**: To support all major web languages to integrate all major SSO services in the world.

**Status**: 
* Supported programming languages include ASP.NET, PHP, and Python. 
* Supported SSO solutions include Facebook, Microsoft, Microsoft Azure AD, Google, Yahoo, LinkedIn, Weibo, and CILogon (which supports nearly a thousand [InCommon participants](https://www.incommon.org/participants/)). The list will grow.

## Demos
[MediaWiki with Facebook login](http://authjs.westus.cloudapp.azure.com)

[HotCRP with Facebook login](http://authjs.westus.cloudapp.azure.com:8000)

## How to use
[**See the instruction**](https://github.com/cs0317/SVAuth/tree/master/SVAuth/adapters). If you want a little more details, here is [**a short paper**](https://github.com/cs0317/SVAuth/blob/master/doc/SVAuth-tool-paper-final.pdf). Also, welcome to [email us](mailto:shuochen@live.com) if you decide to use SVAuth. We can help.  

## Developers
[Matt McCutchen](mailto:%22Matt%20McCutchen%22%20%3Cmatt@mattmccutchen.net%3E),
[Phuong Cao](https://pmcao.github.io),
and [Shuo Chen](http://research.microsoft.com/en-us/people/shuochen/).

Welcome to join us! [Email](mailto:shuochen@live.com) the contact below . 

#### Primary contact
[Shuo Chen](mailto:shuochen@live.com)

## Privacy & Cookies
See [Microsoft Privacy Statement] (https://go.microsoft.com/fwlink/?LinkId=521839)

## Disclaimer
SVAuth uses a technique called self-verifying execution (SVX) to prove the fundamental security properties of SSO systems: an attacker cannot log in to an innocent user's account, and an innocent user cannot be forced to log in to an attacker's account. This technique would catch bugs in the core SSO logic that have occurred in other implementations, such as [forgetting to verify the signature on an identity token](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7191) or [that the token is addressed to the current relying party](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3891). However, like other verification technologies, the verification is based on assumptions and has limitations, such as:

1. It does not cover certain parts of the system, including message parsing, the implementation of crypto operations, and the website adapters;
2. The verified properties do not cover some things that one may consider as "security related", such as privacy and freshness of credentials;
3. The soundness of the SVX mechanism itself has not been rigorously proved starting from lower-level assumptions.

Because of these limitations, we do not guarantee the solution to be free of all security bugs. 

## Earlier repositories (discontinued)

* [AuthPlatelet](https://github.com/AuthPlatelet/AuthPlatelet)
* [AuthJS] (https://github.com/cs0317/AuthClassLib)
