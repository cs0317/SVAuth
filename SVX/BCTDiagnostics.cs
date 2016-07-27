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
// WARNING: If you omit implementation of a static constructor, you are also
// omitting static field initializers that are moved into the static constructor
// by the compiler!
// ~ t-mattmc@microsoft.com 2016-07-14
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Constructor, Inherited = false)]
public class BCTOmitImplementationAttribute : Attribute
{

}

// - We won't support this for assemblies: just don't pass the assembly.
// - Don't consider modules.
// - We won't support this for parameters, etc.
// - Currently BCT doesn't process event and property members at all, but only
//   the underlying accessor methods.  To be able to omit events and properties,
//   we'd need BCT to look them up when it reaches the accessor method.
[AttributeUsage(
    // CCI ITypeDefinition
    AttributeTargets.Class | AttributeTargets.Delegate | AttributeTargets.Enum |
    AttributeTargets.Interface | AttributeTargets.Struct |
    // CCI IMethodDefinition
    AttributeTargets.Method | AttributeTargets.Constructor |
    // CCI IFieldDefinition
    AttributeTargets.Field,
    Inherited = false)]
public class BCTOmitAttribute : Attribute
{

}
