using System;
using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace TameMyCerts.Tests;

public class ETWTests
{
    private readonly ETWLoggerListener _listener;
    private readonly ITestOutputHelper _output;

    public ETWTests(ITestOutputHelper output)
    {
        _output = output;
        _listener = new ETWLoggerListener();
    }

    [Fact]
    public void VerifyEventIDs()
    {
        var loggerType = typeof(ETWLogger);

        var methods = loggerType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        foreach (var method in methods)
        {
            _listener.ClearEvents();
            int? eventId = null;
            // Extract the expected event ID from the method name
            var match = Regex.Match(method.Name, @"\d+");
            if (match.Success)
            {
                eventId = int.Parse(match.Value);
            }
            else
            {
                Assert.Fail($"Event ID not found in method name {method.Name}");
            }

            // Prepare default parameters for the method
            var parameters = method.GetParameters();
            var parameterValues = new object[parameters.Length];
            for (var i = 0; i < parameters.Length; i++)
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
                    _output.WriteLine($"Unknown parameter type {parameters[i].ParameterType}");
                    parameterValues[i] = null;
                }
            }

            _ = method.Invoke(ETWLogger.Log, parameterValues);
            // This checks that there is a event with the correct ID has been registered
            Assert.Equal(eventId, _listener.Events[0].EventId);
            //output.WriteLine($"Found the {method.Name}");
        }
    }
}