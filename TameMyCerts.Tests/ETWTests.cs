using System;
using System.ComponentModel;
using System.Linq;
using Xunit;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using Xunit.Abstractions;
using System.Reflection;
using System.Text.RegularExpressions;

namespace TameMyCerts.Tests
{
    public class ETWTests
    {
        private readonly ITestOutputHelper output;
        private ETWLoggerListener _listener;

        public ETWTests(ITestOutputHelper output)
        {
            this.output = output;
            this._listener = new ETWLoggerListener();
        }

        internal void PrintResult(CertificateRequestValidationResult result)
        {
            output.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
                new Win32Exception(result.StatusCode).Message);
            output.WriteLine(string.Join("\n", result.Description));
        }

        [Fact]
        public void VerifyEventIDs()
        {
            var loggerType = typeof(ETWLogger);

            var methods = loggerType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

            foreach (var method in methods)
            {
                _listener.ClearEvents();
                int? eventID = null;
                // Extract the expected event ID from the method name
                Match match = Regex.Match(method.Name, @"\d+");
                if (match.Success)
                {
                    eventID = int.Parse(match.Value);
                }
                else
                {
                    Assert.Fail($"Event ID not found in method name {method.Name}");
                }

                    // Prepare default parameters for the method
                    var parameters = method.GetParameters();
                var parameterValues = new object[parameters.Length];
                for (int i = 0; i < parameters.Length; i++)
                {
                    if (parameters[i].ParameterType == typeof(string))
                    {
                        parameterValues[i] = "Test message";
                    }
                    else if (parameters[i].ParameterType == typeof(int))
                    {
                        parameterValues[i] = 123;
                    }
                    else if (parameters[i].ParameterType.IsValueType)
                    {
                        parameterValues[i] = Activator.CreateInstance(parameters[i].ParameterType);
                    }
                    else
                    {
                        output.WriteLine($"Unknown parameter type {parameters[i].ParameterType}");
                        parameterValues[i] = null;
                    }
                }
                _ = method.Invoke(ETWLogger.Log, parameterValues);
                // This checks that there is a event with the correct ID has been registered
                Assert.Equal(eventID, _listener.Events[0].EventId);
                //output.WriteLine($"Found the {method.Name}");
            }

        }

    }
}