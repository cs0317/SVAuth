using System;
using System.Diagnostics;

namespace BytecodeTranslator.Diagnostics
{
  public static class BCTDiagnostics {
    /// <summary>
    /// Records the value in execution traces when the program is analyzed using
    /// Bytecode Translator and Boogie.  In normal .NET execution, the value is
    /// logged using Trace.Write.
    /// </summary>
    /// <typeparam name="T">The type of the value to record.</typeparam>
    /// <param name="label">A label for the recorded value.  Must be a string
    /// literal.</param>
    /// <param name="value">The value to record.</param>
    // Unfortunately, there was no existing method in the .NET standard library
    // with the right signature that Bytecode Translator could simply
    // reinterpret.
    public static void Record<T>(string label, T value)
    {
      Trace.Write(label + " = " + value);
    }
  }
}

// The use cases so far are method and /static/ constructor.
// ~ t-mattmc@microsoft.com 2016-07-14
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Constructor, Inherited = false)]
public class BCTOmitImplementationAttribute : Attribute
{

}