using System.IO;
using System.Xml.Serialization;
using AutoFixture;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.Models;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class DataModelSerializationTests
    {
        [TestMethod]
        public void GetPoliciesTypeSerializationTest()
        {
            var sut = new Fixture().Create<CertificateRequestPolicy>();

            var serializer = new XmlSerializer(typeof(CertificateRequestPolicy));

            var stream = new MemoryStream();

            serializer.Serialize(stream, sut);
            stream.Seek(0, SeekOrigin.Begin);
            var output = (CertificateRequestPolicy)serializer.Deserialize(stream);

            output.Should().BeEquivalentTo(sut);
        }
    }
}