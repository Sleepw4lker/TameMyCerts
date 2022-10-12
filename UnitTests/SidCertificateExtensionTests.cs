// Copyright 2021 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts;

namespace UnitTests
{
    [TestClass]
    public class SidCertificateExtensionTests
    {
        [TestMethod]
        public void Result_is_valid()
        {
            const string sid = "S-1-5-21-1381186052-4247692386-135928078-1225";
            const string expectedResult =
                "MD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMzgxMTg2MDUyLTQyNDc2OTIzODYtMTM1OTI4MDc4LTEyMjU=";

            Assert.IsTrue(new SidCertificateExtension(sid).Value.Equals(expectedResult));
        }
    }
}