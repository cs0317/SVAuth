using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVX2
{
    class ParticipantId
    {
        internal Principal principal;
        internal string typeFullName;

        public override bool Equals(object other)
        {
            var other2 = other as ParticipantId;
            return other2 != null && principal == other2.principal && typeFullName == other2.typeFullName;
        }

        public override int GetHashCode()
        {
            return Hasher.Start.With(principal.GetHashCode()).With(typeFullName.GetHashCode());
        }
    }
    abstract class SymT
    {
        // TODO
        internal abstract string MessageTypeFullName { get; }
        internal abstract IEnumerable<SymT> EmbeddedSymTs { get; }
    }
    class SymTNondet : SymT
    {
        internal string messageTypeFullName;

        internal override string MessageTypeFullName => messageTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => new SymT[] { };
    }
    class SymTMethod : SymT
    {
        internal ParticipantId participantId;
        internal string methodName;
        internal string methodReturnTypeFullName;
        internal string[] methodArgTypeFullNames;
        internal SymT[] inputSymTs;

        internal override string MessageTypeFullName => methodReturnTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => inputSymTs;
    }
    class SymTTransfer : SymT
    {
        internal SymT originalSymT;
        // These are non-null if recorded concretely.  Currently, we record all
        // principals and no facets, so avoid a cast in the emit.
        internal Principal producer, sender;

        internal override string MessageTypeFullName => originalSymT.MessageTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => new SymT[] { originalSymT };
    }
#if false
    class NestedSymTEntry
    {
        internal string fieldPath;  // dotted
        internal SymT symT;
    }
    class SymTComposite : SymT
    {
        internal SymT rootSymT;
        internal List<NestedSymTEntry> nestedSymTs;

        internal override string MessageTypeFullName => rootSymT.MessageTypeFullName;
    }
#endif
    class CertificationRequest
    {
        internal SymT scrutineeSymT;
        internal string methodDeclaringTypeFullName;
        internal string methodName;
        internal string methodArgTypeFullName;
        internal ParticipantId[] predicateParticipants;
        internal Principal[] trustedParties;
    }

}
