using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;

namespace SVX
{
    // Add as many as we need.
    public class DeclarablePredicate<T1>
    {
        public void Declare(T1 arg1)
        {
            // It doesn't hurt to let people call this in non-ghost code if they
            // are able to get all the arguments concretely.
            if (VProgram_API.InVProgram)
                Contract.Assume(Check(arg1));
        }
        [BCTOmitImplementation]
        public bool Check(T1 arg1)
        {
            throw new NotImplementedException();
        }
    }

    public class DeclarablePredicate<T1, T2>
    {
        public void Declare(T1 arg1, T2 arg2)
        {
            if (VProgram_API.InVProgram)
                Contract.Assume(Check(arg1, arg2));
        }
        [BCTOmitImplementation]
        public bool Check(T1 arg1, T2 arg2)
        {
            throw new NotImplementedException();
        }
    }
}
