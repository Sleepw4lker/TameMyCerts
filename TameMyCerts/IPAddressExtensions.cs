// See https://docs.microsoft.com/en-us/archive/blogs/knom/ip-address-calculations-with-c-subnetmasks-networks

using System;
using System.Net;

namespace TameMyCerts
{
    public static class IPAddressExtensions
    {

        public static IPAddress GetIpFromString(this string ipInput)
        {
            var returnVal = IPAddress.Any;
            try
            {
                returnVal = IPAddress.Parse(ipInput);
            }
            catch
            {
            }

            return returnVal;
        }

        public static CidrMask GetCidrMask(this string cidrInput)
        {
            var returnVal = new CidrMask();
            var parts = cidrInput.Split('/');
            returnVal.address = BitConverter.ToInt32(IPAddress.Parse(parts[0]).GetAddressBytes(), 0);
            returnVal.mask = IPAddress.HostToNetworkOrder(-1 << (32 - int.Parse(parts[1])));
            return returnVal;
        }

        public static bool IsIp(this string ipInput)
        {
            return !IPAddress.Any.Equals(ipInput.GetIpFromString());
        }

        public static IPAddress GetBroadcastAddress(this IPAddress address, IPAddress subnetMask)
        {
            var ipAddressBytes = address.GetAddressBytes();
            var subnetMaskBytes = subnetMask.GetAddressBytes();
            if (ipAddressBytes.Length != subnetMaskBytes.Length)
                throw new ArgumentException("Lengths of IP address and subnet mask do not match.");
            var broadcastAddress = new byte[ipAddressBytes.Length];
            for (var i = 0; i < broadcastAddress.Length; i++)
                broadcastAddress[i] = (byte) (ipAddressBytes[i] | (subnetMaskBytes[i] ^ 255));
            return new IPAddress(broadcastAddress);
        }

        public static IPAddress GetNetworkAddress(this IPAddress address, IPAddress subnetMask)
        {
            var ipAddressBytes = address.GetAddressBytes();
            var subnetMaskBytes = subnetMask.GetAddressBytes();
            if (ipAddressBytes.Length != subnetMaskBytes.Length)
                throw new ArgumentException("Lengths of IP address and subnet mask do not match.");
            var broadcastAddress = new byte[ipAddressBytes.Length];
            for (var i = 0; i < broadcastAddress.Length; i++)
                broadcastAddress[i] = (byte) (ipAddressBytes[i] & subnetMaskBytes[i]);
            return new IPAddress(broadcastAddress);
        }

        public static bool IsInSameSubnet(this string address1, string address2, string subnetMask)
        {
            var network1 = address1.GetIpFromString();
            var network2 = address2.GetIpFromString();
            var subnet1 = subnetMask.GetIpFromString();
            return network1.IsInSameSubnet(network2, subnet1);
        }

        public static bool IsInSameSubnet(this IPAddress address1, IPAddress address2, IPAddress subnetMask)
        {
            var network1 = address1.GetNetworkAddress(subnetMask);
            var network2 = address2.GetNetworkAddress(subnetMask);
            return network1.Equals(network2);
        }

        public static bool IsInRange(this IPAddress address, string subnetMask)
        {
            var cidrMask = subnetMask.GetCidrMask();
            var ipAddress = BitConverter.ToInt32(address.GetAddressBytes(), 0);
            return (ipAddress & cidrMask.mask) == (cidrMask.address & cidrMask.mask);
        }
    }

    public class CidrMask
    {
        public int address;
        public int mask;
    }
}