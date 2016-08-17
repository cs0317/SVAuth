using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace SVX
{
    [BCTOmit]
    public class MessageStructure<TMessage> where TMessage : SVX_MSG
    {
        abstract class FieldHandler
        {
            internal virtual void Export(TMessage message, PrincipalHandle receiver, PrincipalHandle target) { }
            internal virtual void Extract(TMessage message) { }
            internal virtual void RecordExtract(TMessage message) { }  // Happens even if fake.
            internal virtual void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender) { }
        }

        // TBD how to represent handlers for nested fields.
        Dictionary<string /*fieldName*/, FieldHandler> fieldHandlers = new Dictionary<string, FieldHandler>();

        public bool BrowserOnly { get; set; }

        public MessageStructure()
        {
        }

        // XXX MessageStructures would ideally be immutable, but a simpler API
        // takes priority at the moment.

        class SecretHandler<TSecret> : FieldHandler
            where TSecret : Secret
        {
            internal FieldAccessor<TMessage, TSecret> accessor;
            internal Func<TMessage, PrincipalHandle[]> getKnownReaders;

            internal override void Export(TMessage message, PrincipalHandle receiver, PrincipalHandle target)
            {
                var secret = accessor.Get(message);

                if (secret.knownReaders == null)
                    throw new InvalidOperationException("Secret was never imported??");

                if (!VProgram_API.KnownActsForAny(receiver, secret.knownReaders))
                    throw new Exception("Secret is not allowed to be sent to receiver " + receiver);
                if (target != null && !VProgram_API.KnownActsForAny(target, secret.knownReaders))
                    throw new Exception("Secret is not allowed to be sent to target " + target);
                foreach (var reader in getKnownReaders(message))
                    if (!VProgram_API.KnownActsForAny(reader, secret.knownReaders))
                        throw new Exception("Secret is not allowed to be sent to reader " + reader + " given by message structure");

                secret.exportApproved = true;
            }

            internal override void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender)
            {
                var secret = accessor.Get(message);
                // Automatically infer that the producer and sender must be
                // allowed readers.  This should cover some more cases and put
                // off the need for symbolic secret export checking.
                secret.knownReaders = getKnownReaders(message).Concat(new PrincipalHandle[] { producer, sender }).ToArray();
            }
        }

        public void AddSecret(string fieldName, Func<TMessage, PrincipalHandle[]> getKnownReaders)
        {
            var accessor = FieldLookup.Lookup<TMessage, Secret>(fieldName);
            // Throws if field name already has a handler.
            fieldHandlers.Add(fieldName, new SecretHandler<Secret> {
                accessor = accessor,
                getKnownReaders = getKnownReaders
            });
        }

        class MessagePayloadSecretHandler<TInnerMessage> : SecretHandler<PayloadSecret<TInnerMessage>>
            where TInnerMessage : SVX_MSG
        {
            internal MessagePayloadSecretGenerator<TInnerMessage> generator;
            internal bool verifyOnImport;

            internal override void Extract(TMessage message)
            {
                var secret = accessor.Get(message);
                if (verifyOnImport)
                {
                    generator.VerifyAndExtract(secret);
                }
                else
                {
                    generator.ExtractUnverified(secret);
                }
            }
            internal override void RecordExtract(TMessage message)
            {
                if (verifyOnImport)
                {
                    ((SymTTransfer)message.SVX_symT).payloadSecretsVerifiedOnImport.Add(new VerifyOnImportEntry
                    {
                        fieldPath = accessor.name,
                        secretGeneratorTypeFullName = generator.GetType().FullName
                    });
                    var secret = accessor.Get(message);
                    SVX_Ops.TransferNested(secret.theParams, generator.Signer);
                }
                // If unverified, we leave the SymT inactive, which is weird.
                // XXX: We should TransferNested.  We just need the current
                // principal here in order to generate a facet for the producer.
            }
        }

        public void AddMessagePayloadSecret<TInnerMessage>(string fieldName,
            Func<TMessage, PrincipalHandle[]> getKnownReaders,
            MessagePayloadSecretGenerator<TInnerMessage> generator,
            bool verifyOnImport)
            where TInnerMessage : SVX_MSG
        {
            var accessor = FieldLookup.Lookup<TMessage, PayloadSecret<TInnerMessage>>(fieldName);
            // Throws if field name already has a handler.
            fieldHandlers.Add(fieldName, new MessagePayloadSecretHandler<TInnerMessage>
            {
                accessor = accessor,
                getKnownReaders = getKnownReaders,
                generator = generator,
                verifyOnImport = verifyOnImport
            });
        }

        // target is the redirection target, null if not a redirection.
        //
        // Wow, there's a lot of code that is only used in a small fraction of
        // cases, but I still find it easiest to understand to have all the
        // logic in one method and then define various restricted entry points.
        // ~ t-mattmc@microsoft.com 2016-07-25
        private void Export(bool fake, TMessage message,
            PrincipalHandle receiver, PrincipalHandle target, PrincipalHandle requestProducer)
        {
            if (!fake)
            {
                if (target == null && BrowserOnly)
                    throw new InvalidOperationException("Server attempted to send a browser-only message.");
                foreach (var handler in fieldHandlers.Values)
                {
                    handler.Export(message, receiver, target);
                }
            }
            message.SVX_placeholderRequestProducer = requestProducer;

            // This mainly matters when we use in-process models for remote
            // participants and don't do a real serialize/deserialize pass
            // (currently; maybe we should).  Try to wipe the active flags so we
            // fail secure if the SVX_Ops.Transfer is somehow skipped.  Even
            // when fake = false, we're mutating secrets, so it's reasonable to
            // mutate the message this way as well.
            SVX_Ops.WipeActiveFlags(message);
        }

        public void Export(TMessage message, PrincipalHandle receiver, PrincipalHandle target)
        {
            Export(false, message, receiver, target, null);
        }
        public void FakeExport(TMessage message)
        {
            Export(true, message, null, null, null);
        }

        // For cleanliness in serialization, provide a separate API so that
        // message.SVX_placeholderRequestProducer is only set when we expect the
        // receiver to use it.
        public void ExportDirectResponse(TMessage message, PrincipalHandle receiver, PrincipalHandle requestProducer)
        {
            Export(false, message, receiver, null, requestProducer);
        }
        public void FakeExportDirectResponse(TMessage message, PrincipalHandle requestProducer)
        {
            Export(true, message, null, null, requestProducer);
        }

        private void Import(bool fake, TMessage message, Action modelAction,
            PrincipalHandle producer, PrincipalHandle sender, PrincipalHandle realRequestProducer)
        {
            // Extract all fields before importing any, in case getKnownReaders
            // for one secret references information extracted from another
            // field.
            if (!fake)
            {
                foreach (var handler in fieldHandlers.Values)
                {
                    handler.Extract(message);
                }
            }

            // Helpful VS suggestion... https://msdn.microsoft.com/en-us/library/dn986595.aspx
            modelAction?.Invoke();

            // Set up secretsVerifiedOnImport field so RecordExtract can add to it.
            SVX_Ops.Transfer(message, producer, sender, realRequestProducer, BrowserOnly);

            foreach (var handler in fieldHandlers.Values)
            {
                handler.RecordExtract(message);
                if (!fake)
                {
                    handler.Import(message, producer, sender);
                }
            }
        }

        public void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender)
        {
            Import(false, message, null, producer, sender, null);
        }

        /* The modelAction is called after any configured payload tokens/secrets
         * have been extracted but before any SymT processing.  It should use
         * fake operations (SVX_Ops.FakeCall, MessageStructure.Fake*) to fill in
         * the SymTs of the message being imported and any relevant nested
         * messages to represent the path assumed to have been taken to produce
         * their data.
         *
         * (Emphasis on "assumed"!  Even if we have faithful models of all
         * participants, proving that the assumed path is the only path that
         * reaches the import is in general a whole-protocol verification
         * problem.  Since such proofs require a very different style of
         * reasoning than normal use of SVX, we are not attempting to extend the
         * SVX framework to provide any help with them at this time.  So in the
         * worst case, the use of models with an assumed path severely weakens
         * the assurance that SVX provides.)
         */
        public void ImportWithModel(TMessage message, Action modelAction, PrincipalHandle producer, PrincipalHandle sender)
        {
            Import(false, message, modelAction, producer, sender, null);
        }
        public void FakeImport(TMessage message, PrincipalHandle producer, PrincipalHandle sender)
        {
            Import(true, message, null, producer, sender, null);
        }

        // TODO: client needs to tie in to some ambient "current principal" variable
        private void ImportDirectResponse(bool fake, TMessage message, Action modelAction, PrincipalHandle server, PrincipalHandle client)
        {
            Import(fake, message, modelAction, server, server, client);
        }

        public void ImportDirectResponse(TMessage message, PrincipalHandle server, PrincipalHandle client)
        {
            ImportDirectResponse(false, message, null, server, client);
        }
        public void ImportDirectResponseWithModel(TMessage message, Action modelAction, PrincipalHandle server, PrincipalHandle client)
        {
            ImportDirectResponse(false, message, modelAction, server, client);
        }
        public void FakeImportDirectResponse(TMessage message, PrincipalHandle server, PrincipalHandle client)
        {
            ImportDirectResponse(true, message, null, server, client);
        }
    }
}
