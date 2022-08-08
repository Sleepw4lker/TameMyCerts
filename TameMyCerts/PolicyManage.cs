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

using System.Reflection;
using System.Runtime.InteropServices;
using CERTPOLICYLib;

namespace TameMyCerts
{
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    [ProgId("TameMyCerts.PolicyManage")]
    [Guid("f24389a5-97a6-40c1-a1c6-aefd273fb634")] // must be distinct from Policy Class
    public class PolicyManage : CCertManagePolicyModule
    {
        #region ICertManageModule Members

        public void Configure(string strConfig, string strStorageLocation, int flags)
        {
            // This method is intended for future functionality.
        }

        public object GetProperty(string strConfig, string strStorageLocation, string strPropertyName, int flags)
        {
            var assembly = Assembly.GetExecutingAssembly();

            switch (strPropertyName) // Each of these is required
            {
                case "Name":
                    return ((AssemblyTitleAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyTitleAttribute))).Title;

                case "Description":
                    return ((AssemblyDescriptionAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyDescriptionAttribute))).Description;

                case "Copyright":
                    return ((AssemblyCopyrightAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyCopyrightAttribute))).Copyright;

                case "File Version":
                    return ((AssemblyFileVersionAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyFileVersionAttribute))).Version;

                case "Product Version":
                    return ((AssemblyVersionAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyVersionAttribute))).Version;

                default:
                    return $"Unknown Property: {strPropertyName}";
            }
        }

        public void SetProperty(string strConfig, string strStorageLocation, string strPropertyName, int flags,
            ref object pvarProperty)
        {
            // This method is intended for future functionality.
        }

        #endregion
    }
}