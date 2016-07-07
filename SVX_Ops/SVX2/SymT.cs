using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVX2
{
    abstract class SymT
    {
        // TODO
        internal abstract string TypeFullName { get; }
    }
    class SymTNondet : SymT
    {
        internal string typeFullName;

        internal override string TypeFullName => typeFullName;
    }
    class SymTMethod : SymT
    {
        internal Principal principal;
        internal string runtimeTypeFullName;
        internal string methodName;
        internal string methodReturnTypeFullName;
        internal string[] methodArgTypeFullNames;
        internal SymT[] inputSymTs;

        internal override string TypeFullName => methodReturnTypeFullName;
    }
    class SymTTransfer : SymT
    {
        internal SymT originalSymT;
        // These are non-null if recorded concretely.  Currently, we record all
        // principals and no facets, so avoid a cast in the emit.
        internal Principal producer, sender;

        internal override string TypeFullName => originalSymT.TypeFullName;
    }
    class NestedSymTEntry
    {
        internal string fieldPath;  // dotted
        internal SymT symT;
    }
    class SymTComposite : SymT
    {
        internal SymT rootSymT;
        internal List<NestedSymTEntry> nestedSymTs;

        internal override string TypeFullName => rootSymT.TypeFullName;
    }
    class CertificationRequest
    {
        internal SymT scrutineeSymT;
        internal string methodDeclaringTypeFullName;
        internal string methodName;
        internal string methodArgTypeFullName;
        internal Principal[] trustedParties;
    }

}
