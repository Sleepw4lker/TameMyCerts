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

using System;
using System.Net;

namespace TameMyCerts
{
    public static class IPAddressExtensions
    {
        public static bool IsInRange(this IPAddress address, string subnetMask)
        {
            var cidrMask = CidrMask.Parse(subnetMask);
            var ipAddress = BitConverter.ToInt32(address.GetAddressBytes(), 0);
            return (ipAddress & cidrMask.Mask) == (cidrMask.Address & cidrMask.Mask);
        }
    }

    internal struct CidrMask
    {
        public int Address { get; }
        public int Mask { get; }

        private CidrMask(int address, int mask)
        {
            Address = address;
            Mask = mask;
        }

        public static CidrMask Parse(string cidrInput)
        {
            var parts = cidrInput.Split('/');
            return new CidrMask(
                BitConverter.ToInt32(IPAddress.Parse(parts[0]).GetAddressBytes(), 0),
                IPAddress.HostToNetworkOrder(-1 << (32 - int.Parse(parts[1])))
            );
        }
    }
}