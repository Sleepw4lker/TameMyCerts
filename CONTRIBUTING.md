# Contributing to the TameMyCerts project

Hello, and welcome.

First of all, contributions of any kind are highly welcome.

These may be...
- Requesting or suggesting features and improvements
- Supporting Users
- Fixing Bugs
- Implementing features or Tests
- Writing Documentation
- Security testing

## Philosophy

TameMyCerts aims to be of Enterprise grade quality, in terms of reliability, security and performance. Therefore, please ensure that all implemented features are of high quality, are documented and are backed by tests. If you implement advanced functionality, please also commit on supporting these on the long run.

## Developing

### Architecture decisions

- Using the "older" .NET Framework 4.7.2 was done intentionally to avoid having to install any dependency on production servers. At the time of project start this was the default for Windows Server 2019, and (for now) is under Long-term support by Microsoft.
- Same goes for the decision to not use external dependencies or 3rd party packages of any kind. If a function is not provided by the .NET Framework, you must implement it on your own.
- It is OK to use Win32 COM APIs as the policy module will by nature always require to run on a Windows operating system.
- The module aims to support all Windows Server (and Active Directory) deployments that are under [active support by Microsoft](https://learn.microsoft.com/en-us/lifecycle/products/) at time of release.
- The code structure is split into a part that "can be Unit tested" and a part that cannot.
    - Therefore, the parts that require to directly interact with the Server OS (Logging) or the CA Service (ICertPolicy, ICertPolicyManage, and ICertServerPolicy callbacks) should contain the least amount of code possible. To test these implementations, there is a set of Pester Tests and a Framework to reproducibly set up a virtual test environment under the `TameMyCerts.IntegrationTests` folder.
    - The part that can be Unit-tested is mostly implemented in "Validators" that should not contain direct interaction with the CA service or logging.

### Setting up the development environment

> You can develop and and build the solution on an ordinary Windows client machine. No need to deploy Visual Studio on a CA server.

TameMyCerts uses .NET Framework 4.7.2, so ensure you have the following installed in Visual Studio:

- .NET Desktop Development
- .NET Framework 4.7.2 SDK

### Building the module

If you want to build the module from source, call the supplied build scripts from the Visual Studio Developer command prompt:

1. You will first have to run the included [make_il.cmd](TameMyCerts/make_il.cmd) to build the necessary interop-libraries, if you do not trust the included Interop DLL files.
2. Running [make_debug.cmd](TameMyCerts/make_debug.cmd) will create a debug build (does not increment version number).