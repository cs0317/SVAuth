# SVAuth: Self-verifying single-sign-on solutions

<img src="logo1.jpg" style="width: 200px;"/>
SVAuth tries to provide the simplest and the most secure integration solution for a website to integrate single-sign-on (SSO) services. It is so simple that a website programmer doesn't need to know anything about SSO protocols or implementations. It is secure because every user login is formally proved for the correctness of its core logic by the state-of-the-art program verifier. 

If your website needs SSO login, don't be overwhelmed by all kinds of libraries and protocol documents. Try SVAuth. It may save you tons of time and effort, and save your website from several types of security bugs!

## Goal and status

**Goal**: To support all major web languages to integrate all major SSO services in the world.

**Status**: Currently support ASP.NET and PHP. Current SSO solutions include Facebook, Microsoft, Microsoft Azure AD, Google, Yahoo, LinkedIn and Weibo. The list will grow.

## Demos
[MediaWiki with Facebook login](http://authjs.westus.cloudapp.azure.com)

[HotCRP with Facebook login](http://authjs.westus.cloudapp.azure.com:8000)

## How to use
The easiest way to use SVAuth is through the “website adapter”. [**See the instruction**]( https://github.com/cs0317/SVAuth/tree/master/SVAuth/Adapters). Also, welcome to [email us](mailto:shuochen@live.com) if you decide to use SVAuth. We can help.  

## Developers
[Matt McCutchen](mailto:%22Matt%20McCutchen%22%20%3Cmatt@mattmccutchen.net%3E),
[Phuong Cao](https://www.linkedin.com/in/pmcao),
and [Shuo Chen](http://research.microsoft.com/en-us/people/shuochen/).

Welcome to join us! [Email](mailto:shuochen@live.com) the contact below . 

#### Primary contact
[Shuo Chen](mailto:shuochen@live.com)

## Disclaimer
SVAuth uses a technique called self-verifying execution (SVX) to proven important security properties for SSO systems. However, like other verification technologies, the verification is based on assumptions and has limitations, such as:

(1) It does not cover message parsing, or the details of crypto operations;
(2) The verified properties do not cover everything that one may consider as "security related";
(3) There are components, like the website adaptors and the underlying SVX mechanism, that are not subject to SVX verification.

Because of these limitations, we do not guarantee the solution to be free of all security bugs. 

## Earlier repositories (discontinued)

* [AuthPlatelet](https://github.com/AuthPlatelet/AuthPlatelet)
* [AuthJS] (https://github.com/cs0317/AuthClassLib)