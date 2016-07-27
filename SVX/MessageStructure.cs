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
            internal virtual void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender) { }
            internal virtual void Extract(bool fake, TMessage message) { }
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

            internal override void Extract(bool fake, TMessage message)
            {
                var secret = fake ? null : accessor.Get(message);
                if (verifyOnImport)
                {
                    if (!fake)
                    {
                        generator.VerifyAndExtract(secret);
                    }
                    ((SymTTransfer)message.SVX_symT).payloadSecretsVerifiedOnImport.Add(new VerifyOnImportEntry {
                        fieldPath = accessor.name,
                        secretGeneratorTypeFullName = generator.GetType().FullName
                    });
                }
                else
                {
                    if (!fake)
                    {
                        generator.ExtractUnverified(secret);
                    }
                }
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

        private void Import(bool fake, TMessage message, PrincipalHandle producer, PrincipalHandle sender, PrincipalHandle realRequestProducer)
        {
            // Set up secretsVerifiedOnImport field so Extract can add to it.
            SVX_Ops.Transfer(message, producer, sender, realRequestProducer, BrowserOnly);

            // Extract all fields before importing any, in case getKnownReaders
            // for one secret references information extracted from another
            // field.
            foreach (var handler in fieldHandlers.Values)
            {
                handler.Extract(fake, message);
            }
            if (!fake)
            {
                foreach (var handler in fieldHandlers.Values)
                {
                    handler.Import(message, producer, sender);
                }
            }
        }

        public void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender)
        {
            Import(false, message, producer, sender, null);
        }
        public void FakeImport(TMessage message, PrincipalHandle producer, PrincipalHandle sender)
        {
            Import(true, message, producer, sender, null);
        }

        // TODO: client needs to tie in to some ambient "current principal" variable
        private void ImportDirectResponse(bool fake, TMessage message, PrincipalHandle server, PrincipalHandle client)
        {
            Import(fake, message, server, server, client);
        }

        public void ImportDirectResponse(TMessage message, PrincipalHandle server, PrincipalHandle client)
        {
            ImportDirectResponse(false, message, server, client);
        }
        public void FakeImportDirectResponse(TMessage message, PrincipalHandle server, PrincipalHandle client)
        {
            ImportDirectResponse(true, message, server, client);
        }
    }
}
