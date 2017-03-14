using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVX
{
    // NOTICE: Both the SymT deserialization code and the subsequent SymT
    // processing code (e.g., VProgramEmitter) have known weaknesses in dealing
    // with untrusted input.  So don't deserialize untrusted SymTs.  For now, we
    // don't need to because we're only using model remote parties, and
    // SVX_MSG.SVX_symT is excluded from serialization.
    //
    // XXX: Is there a way to ensure that SymT fields never get implicitly
    // deserialized without an annotation saying "no untrusted input"?

    // Non-public fields don't get serialized by default.  I don't feel like
    // making them all public just for this.  For now,
    // MemberSerialization.Fields does what we want.

    // Like ParticipantId but doesn't contain an actual Type object, so easier
    // to serialize.
    [BCTOmit]
    [JsonObject(MemberSerialization.Fields)]
    class SymTParticipantId
    {
        internal Entity principal;
        internal string typeFullName;

        public override bool Equals(object other)
        {
            var other2 = other as SymTParticipantId;
            return other2 != null && principal == other2.principal && typeFullName == other2.typeFullName;
        }

        public override int GetHashCode()
        {
            return Hasher.Start.With(principal.GetHashCode()).With(typeFullName.GetHashCode());
        }
    }

    // Note: For now, SymTs should be deserialized with TypeNameHandling.All.
    // There doesn't seem to be an easy way to specify this here rather than on
    // every reference to the SymT class.
    [BCTOmit]
    abstract class SymT
    {
        // Generate a fresh one by default.  This will just be wasted work and
        // get overwritten when deserializing.
        internal string messageId = Utils.RandomIdString();

        internal abstract string MessageTypeFullName { get; }
        internal abstract IEnumerable<SymT> EmbeddedSymTs { get; }
        // This only goes one level down.  It means the caller has to do the
        // recursion, but also means the caller has control of the recursion
        // (e.g., whether it happens before or after rewriting the root, both,
        // or neither in certain cases) without us having to provide multiple
        // variants of this method.
        internal abstract SymT RewriteEmbeddedSymTs(Func<SymT, SymT> rewriter);
    }

    [BCTOmit]
    [JsonObject(MemberSerialization.Fields)]
    class SymTNondet : SymT
    {
        internal string messageTypeFullName;

        internal override string MessageTypeFullName => messageTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => new SymT[] { };
        internal override SymT RewriteEmbeddedSymTs(Func<SymT, SymT> rewriter) => this;
    }

    [BCTOmit]
    [JsonObject(MemberSerialization.Fields)]
    class SymTMethod : SymT
    {
        internal SymTParticipantId participantId;
        internal string methodName;
        internal string methodReturnTypeFullName;
        internal string[] methodArgTypeFullNames;

        // Careful: contains nulls for nondet non-message arguments.
        [JsonProperty(ItemTypeNameHandling = TypeNameHandling.All)]
        internal SymT[] inputSymTs;

        internal override string MessageTypeFullName => methodReturnTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs => inputSymTs.Where((symT) => symT != null);
        internal override SymT RewriteEmbeddedSymTs(Func<SymT, SymT> rewriter) =>
            new SymTMethod
            {
                messageId = messageId,
                participantId = participantId,
                methodName = methodName,
                methodReturnTypeFullName = methodReturnTypeFullName,
                methodArgTypeFullNames = methodArgTypeFullNames,
                inputSymTs = inputSymTs.Select(
                    (symT) => (symT == null) ? null : rewriter(symT)).ToArray()
            };
    }

    [BCTOmit]
    class VerifyOnImportEntry
    {
        internal string fieldPath;
        internal string secretGeneratorTypeFullName;
    }
    [BCTOmit]
    [JsonObject(MemberSerialization.Fields)]
    class SymTTransfer : SymT
    {
        public SymTTransfer() { }
        internal SymTTransfer(SymTTransfer copyFrom)
        {
            // XXX Aliasing
            messageId = copyFrom.messageId;
            originalSymT = copyFrom.originalSymT;
            hasSender = copyFrom.hasSender;
            producer = copyFrom.producer;
            sender = copyFrom.sender;
            browserOnly = copyFrom.browserOnly;
            payloadSecretsVerifiedOnImport = copyFrom.payloadSecretsVerifiedOnImport;
            fallback = copyFrom.fallback;
        }

        [JsonProperty(TypeNameHandling = TypeNameHandling.All)]
        internal SymT originalSymT;

        internal bool hasSender;

        // In general, the producer should be filled in even if it is a facet,
        // in case it is a direct client that we're going to replace.  Let's do
        // the same for the sender to maintain consistency.  Facets get erased
        // when we actually prepare a CertificationRequest.
        internal Principal producer, sender;

        internal bool browserOnly;

        // This one is a list so we can mutate it little by little during import. :/
        internal List<VerifyOnImportEntry> payloadSecretsVerifiedOnImport = new List<VerifyOnImportEntry>();

        // SymT we should use if we don't trust the transfer.  This should never
        // be stored in a message; it's used temporarily by the VProgramEmitter.
        internal SymT fallback;

        internal override string MessageTypeFullName => originalSymT.MessageTypeFullName;
        internal override IEnumerable<SymT> EmbeddedSymTs =>
            fallback == null ? new SymT[] { originalSymT } : new SymT[] { originalSymT, fallback };
        internal override SymT RewriteEmbeddedSymTs(Func<SymT, SymT> rewriter) =>
            new SymTTransfer
            {
                messageId = messageId,
                originalSymT = rewriter(originalSymT),
                hasSender = hasSender,
                producer = producer,
                sender = sender,
                browserOnly = browserOnly,
                payloadSecretsVerifiedOnImport = payloadSecretsVerifiedOnImport,
                fallback = (fallback == null) ? null : rewriter(fallback),
            };
    }

    [BCTOmit]
    [JsonObject(MemberSerialization.Fields)]
    class NestedSymTEntry
    {
        internal string fieldPath;  // dotted
        internal SymT symT;
    }
    [BCTOmit]
    [JsonObject(MemberSerialization.Fields)]
    class SymTComposite : SymT
    {
        internal SymT rootSymT;
        internal NestedSymTEntry[] nestedSymTs;

        internal override string MessageTypeFullName => rootSymT.MessageTypeFullName;

        // SymTComposite shares the messageId of its rootSymT.  It's unfortunate
        // that the messageId gets redundantly serialized, but not worth
        // complicating things to avoid.  This setter lets us continue to use
        // the object initializer syntax.
        internal SymT RootSymTWithMessageId
        {
            set
            {
                rootSymT = value;
                messageId = rootSymT.messageId;
            }
        }

        internal override IEnumerable<SymT> EmbeddedSymTs =>
            new SymT[] { rootSymT }.Concat(nestedSymTs.Select((e) => e.symT));
        internal override SymT RewriteEmbeddedSymTs(Func<SymT, SymT> rewriter) =>
            new SymTComposite
            {
                RootSymTWithMessageId = rewriter(rootSymT),
                nestedSymTs = nestedSymTs.Select((entry) => new NestedSymTEntry {
                    fieldPath = entry.fieldPath,
                    symT = rewriter(entry.symT)
                }).ToArray()
            };
    }

    [BCTOmit]
    [JsonObject(MemberSerialization.Fields)]
    class CertificationRequest
    {
        [JsonProperty(TypeNameHandling = TypeNameHandling.All)]
        internal SymT scrutineeSymT;
        internal SymTParticipantId participantId;
        //internal string methodDeclaringTypeFullName;
        internal string methodName;
        internal string methodArgTypeFullName;
        internal SymTParticipantId[] predicateParticipants;

        // Implement Equals and HashCode so we can cache the result of a
        // CertificationRequest.

        public override bool Equals(object obj)
        {
            var that = obj as CertificationRequest;
            return (that != null && JsonConvert.SerializeObject(this) == JsonConvert.SerializeObject(that));
        }

        public override int GetHashCode()
        {
            return JsonConvert.SerializeObject(this).GetHashCode();
        }
    }

}
