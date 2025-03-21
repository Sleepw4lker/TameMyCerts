# Contributing to the TameMyCerts project

Hello, and welcome.

First of all, contributions of are highly welcome.

These may be...

- Signing up for a Maintenance Contract. Keep in mind that we as the developers are giving the high quality product out to you for free. If you are serious about your IT security, you should also not to hesitate to help the developers make a living by developing and supporting TameMyCerts.
- Requesting, suggesting, and refining features
- Supporting Users
- Finding, reporting, and fixing Bugs
- Auditing the code base 
- Implementing features or Tests
- Writing Documentation
- Testing for Security issues
- Promoting TameMyCerts on social media, with your coworkers, and at your clients
- Donating to charity, and telling us about it

## Philosophy

TameMyCerts aims to be of Enterprise grade quality, in terms of reliability, security and performance.
Therefore, please **ensure that your controbutions are of high quality**, are documented and are backed by tests.
If you implement new features that may require special knowledge or equipment, **please also commit yourself to support these on the long run**.

## Developing

### Architecture decisions

- Using the "older" .NET Framework 4.7.2 was done intentionally to avoid having to install (and having to patch) any dependency on production servers. At the time of project start this was the default for Windows Server 2019, and (for now) is under Long-term support by Microsoft.
- Same goes for the decision to not use external dependencies or 3rd party packages of any kind. If a function is not provided by the .NET Framework, you must implement it on your own.
- It is OK to use Win32 COM APIs as the policy module will by nature always require to run on a Windows operating system.
- The module aims to support all Windows Server (and Active Directory) deployments that are under [active support by Microsoft](https://learn.microsoft.com/en-us/lifecycle/products/) at time of release. This also means kepping older operating systems supported is entirely optional and can be omitted if it would result in better and cleaner code.
- The code structure is split into a part that can be Unit-tested and a part that cannot.
    - The parts that require to directly interact with the Server Operating System (Logging or File System access) or the CA Service ([ICertPolicy](TameMyCerts/Policy.cs) and [ICertPolicyManage](TameMyCerts/PolicyManage.cs) implementations, as well as ICertServerPolicy callbacks to the CA service) should contain the least amount of code that is possible. To test these parts of the code, there is a set of Pester Tests and a Framework to reproducibly set up a virtual test environment under the `TameMyCerts.IntegrationTests` folder.
    - The parts that can be Unit-tested is mostly implemented in "Validators" that should not contain code that directly interacts with the CA service or Server Operating System.

### Setting up the development environment

Ensure you have the following installed in Visual Studio:

- .NET Desktop Development
- .NET Framework 4.7.2 SDK

### Building the module

If you want to build the module from source, call the supplied build scripts from the Visual Studio Developer command prompt:

1. You will first have to run the included [make_il.cmd](TameMyCerts/make_il.cmd) to build the necessary interop-libraries, if you do not trust the included Interop DLL files.
2. Running [make_debug.cmd](TameMyCerts/make_debug.cmd) will create a debug build.