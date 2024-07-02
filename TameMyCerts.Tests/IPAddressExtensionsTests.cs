using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.ClassExtensions;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class IPAddressExtensionsTests
    {
        [TestMethod]
        public void Invalid_data_is_no_match()
        {
            Assert.IsFalse(IPAddress.Parse("10.0.0.1").IsInRange("10.0.0.0/test"));
            Assert.IsFalse(IPAddress.Parse("10.0.0.1").IsInRange("test"));
            Assert.IsFalse(IPAddress.Parse("10.0.0.1").IsInRange("test/0"));
            Assert.IsFalse(IPAddress.Parse("10.0.0.1").IsInRange("test/-1"));
            Assert.IsFalse(IPAddress.Parse("192.168.0.1").IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsFalse(IPAddress.Parse("0.0.0.0").IsInRange("0.0.0.0/33"));
            Assert.IsFalse(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:0012::0/-1"));
            Assert.IsFalse(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:0012::0/129"));
        }

        [TestMethod]
        public void IPv4_in_subnet_is_match()
        {
            Assert.IsTrue(IPAddress.Parse("0.0.0.0").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("10.0.0.1").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("172.16.0.1").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.1").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("255.255.255.255").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("0.0.0.0").IsInRange("0.0.0.0/32"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.0").IsInRange("192.168.0.0/24"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.1").IsInRange("192.168.0.0/24"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.255").IsInRange("192.168.0.0/24"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.0").IsInRange("192.168.0.0/16"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.1").IsInRange("192.168.0.0/16"));
            Assert.IsTrue(IPAddress.Parse("192.168.255.255").IsInRange("192.168.0.0/16"));
            Assert.IsTrue(IPAddress.Parse("172.16.0.0").IsInRange("172.16.0.0/12"));
            Assert.IsTrue(IPAddress.Parse("172.16.0.1").IsInRange("172.16.0.0/12"));
            Assert.IsTrue(IPAddress.Parse("172.31.255.255").IsInRange("172.16.0.0/12"));
            Assert.IsTrue(IPAddress.Parse("10.0.0.0").IsInRange("10.0.0.0/8"));
            Assert.IsTrue(IPAddress.Parse("10.0.0.1").IsInRange("10.0.0.0/8"));
            Assert.IsTrue(IPAddress.Parse("10.255.255.255").IsInRange("10.0.0.0/8"));
            Assert.IsTrue(IPAddress.Parse("192.168.5.1").IsInRange("192.168.5.85/24"));
            Assert.IsTrue(IPAddress.Parse("192.168.5.254").IsInRange("192.168.5.85/24"));
            Assert.IsTrue(IPAddress.Parse("10.128.240.48").IsInRange("10.128.240.50/30"));
            Assert.IsTrue(IPAddress.Parse("10.128.240.49").IsInRange("10.128.240.50/30"));
            Assert.IsTrue(IPAddress.Parse("10.128.240.50").IsInRange("10.128.240.50/30"));
            Assert.IsTrue(IPAddress.Parse("10.128.240.51").IsInRange("10.128.240.50/30"));
            Assert.IsTrue(IPAddress.Parse("0.0.0.0").IsInRange("192.168.5.85/0"));
            Assert.IsTrue(IPAddress.Parse("255.255.255.255").IsInRange("192.168.5.85/0"));
        }

        [TestMethod]
        public void IPv4_not_in_subnet_is_no_match()
        {
            Assert.IsFalse(IPAddress.Parse("0.0.0.1").IsInRange("0.0.0.0/32"));
            Assert.IsFalse(IPAddress.Parse("10.0.0.1").IsInRange("0.0.0.0/32"));
            Assert.IsFalse(IPAddress.Parse("172.16.0.1").IsInRange("0.0.0.0/32"));
            Assert.IsFalse(IPAddress.Parse("192.168.0.1").IsInRange("0.0.0.0/32"));
            Assert.IsFalse(IPAddress.Parse("255.255.255.255").IsInRange("0.0.0.0/32"));
            Assert.IsFalse(IPAddress.Parse("11.0.0.1").IsInRange("10.0.0.0/8"));
            Assert.IsFalse(IPAddress.Parse("172.32.0.1").IsInRange("172.16.0.0/16"));
            Assert.IsFalse(IPAddress.Parse("192.169.0.1").IsInRange("192.168.0.0/16"));
            Assert.IsFalse(IPAddress.Parse("192.168.1.1").IsInRange("192.168.0.0/24"));
            Assert.IsFalse(IPAddress.Parse("192.168.4.254").IsInRange("192.168.5.85/24"));
            Assert.IsFalse(IPAddress.Parse("191.168.5.254").IsInRange("192.168.5.85/24"));
            Assert.IsFalse(IPAddress.Parse("10.128.240.47").IsInRange("10.128.240.50/30"));
            Assert.IsFalse(IPAddress.Parse("10.128.240.52").IsInRange("10.128.240.50/30"));
            Assert.IsFalse(IPAddress.Parse("10.128.239.50").IsInRange("10.128.240.50/30"));
            Assert.IsFalse(IPAddress.Parse("10.127.240.51").IsInRange("10.128.240.50/30"));
        }

        [TestMethod]
        public void IPv6_in_subnet_is_match()
        {
            Assert.IsTrue(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsTrue(IPAddress.Parse("2001:0DB8:ABCD:0012:FFFF:FFFF:FFFF:FFFF")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsTrue(IPAddress.Parse("2001:0DB8:ABCD:0012:0001:0000:0000:0000")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsTrue(IPAddress.Parse("2001:0DB8:ABCD:0012:FFFF:FFFF:FFFF:FFF0")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsTrue(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:0012::0/128"));
            Assert.IsTrue(IPAddress.Parse("2001:0db8:abcd:5000:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:5678::0/53"));
            Assert.IsTrue(IPAddress.Parse("2001:0db8:abcd:57ff:ffff:ffff:ffff:ffff")
                .IsInRange("2001:db8:abcd:5678::0/53"));
            Assert.IsTrue(IPAddress.Parse("::")
                .IsInRange("2001:db8:abcd:0012::0/0"));
            Assert.IsTrue(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
                .IsInRange("2001:db8:abcd:0012::0/0"));
        }

        [TestMethod]
        public void IPv6_not_in_subnet_is_no_match()
        {
            Assert.IsFalse(IPAddress.Parse("2001:0DB8:ABCD:0011:FFFF:FFFF:FFFF:FFFF")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsFalse(IPAddress.Parse("2001:0DB8:ABCD:0013:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsFalse(IPAddress.Parse("2001:0DB8:ABCD:0013:0001:0000:0000:0000")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsFalse(IPAddress.Parse("2001:0DB8:ABCD:0011:FFFF:FFFF:FFFF:FFF0")
                .IsInRange("2001:db8:abcd:0012::0/64"));
            Assert.IsFalse(IPAddress.Parse("2001:0DB8:ABCD:0012:0000:0000:0000:0001")
                .IsInRange("2001:db8:abcd:0012::0/128"));
            Assert.IsFalse(IPAddress.Parse("2001:0db8:abcd:4999:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:5678::0/53"));
            Assert.IsFalse(IPAddress.Parse("2001:0db8:abcd:5800:0000:0000:0000:0000")
                .IsInRange("2001:db8:abcd:5678::0/53"));
        }
    }
}