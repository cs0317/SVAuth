using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVX2
{
    // Non-public fields don't get serialized by default.  I don't feel like
    // making them all public just for this.  For now,
    // MemberSerialization.Fields does what we want.

    [JsonObject(MemberSerialization.Fields)]
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
    [JsonObject(MemberSerialization.Fields)]
    class SymTNondet : SymT
    {
        internal string messageTypeFullName;

        internal override string MessageTypeFullName => messageTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => new SymT[] { };
    }
    [JsonObject(MemberSerialization.Fields)]
    class SymTMethod : SymT
    {
        internal ParticipantId participantId;
        internal string methodName;
        internal string methodReturnTypeFullName;
        internal string[] methodArgTypeFullNames;
        [JsonProperty(ItemTypeNameHandling = TypeNameHandling.All)]
        internal SymT[] inputSymTs;

        internal override string MessageTypeFullName => methodReturnTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => inputSymTs;
    }
    class VerifyOnImportEntry
    {
        internal string fieldPath;
        internal string secretGeneratorTypeFullName;
    }
    [JsonObject(MemberSerialization.Fields)]
    class SymTTransfer : SymT
    {
        public SymTTransfer() { }
        internal SymTTransfer(SymTTransfer copyFrom)
        {
            // XXX Aliasing
            originalSymT = copyFrom.originalSymT;
            hasSender = copyFrom.hasSender;
            producer = copyFrom.producer;
            sender = copyFrom.sender;
            payloadSecretsVerifiedOnImport = copyFrom.payloadSecretsVerifiedOnImport;
            fallback = copyFrom.fallback;
        }

        [JsonProperty(TypeNameHandling = TypeNameHandling.All)]
        internal SymT originalSymT;

        internal bool hasSender;
        // These are non-null if recorded concretely.  Currently, we record all
        // principals and no facets, so avoid a cast in the emit.
        internal Principal producer, sender;

        // This one is a list so we can mutate it little by little during import. :/
        internal List<VerifyOnImportEntry> payloadSecretsVerifiedOnImport = new List<VerifyOnImportEntry>();

        // SymT we should use if we don't trust the transfer.  This should never
        // be stored in a message; it's used temporarily by the VProgramEmitter.
        internal SymT fallback;

        internal override string MessageTypeFullName => originalSymT.MessageTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => new SymT[] { originalSymT };
    }
    [JsonObject(MemberSerialization.Fields)]
    class NestedSymTEntry
    {
        internal string fieldPath;  // dotted
        internal SymT symT;
    }
    [JsonObject(MemberSerialization.Fields)]
    class SymTComposite : SymT
    {
        internal SymT rootSymT;
        internal NestedSymTEntry[] nestedSymTs;

        internal override string MessageTypeFullName => rootSymT.MessageTypeFullName;

        internal override IEnumerable<SymT> EmbeddedSymTs =>
            new SymT[] { rootSymT }.Concat(nestedSymTs.Select((e) => e.symT));
    }

    // We don't actually serialize this yet, but we will once we have the
    // certification server.
    [JsonObject(MemberSerialization.Fields)]
    class CertificationRequest
    {
        [JsonProperty(TypeNameHandling = TypeNameHandling.All)]
        internal SymT scrutineeSymT;
        internal string methodDeclaringTypeFullName;
        internal string methodName;
        internal string methodArgTypeFullName;
        internal ParticipantId[] predicateParticipants;
        internal Principal[] trustedParties;
    }

}
