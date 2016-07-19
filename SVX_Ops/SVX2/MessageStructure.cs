using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace SVX2
{
    public class MessageStructure<TMessage> where TMessage : SVX_MSG
    {
        abstract class FieldHandler
        {
            internal virtual void Export(TMessage message, PrincipalHandle receiver, PrincipalHandle target) { }
            internal virtual void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender) { }
            internal virtual void Extract(TMessage message) { }
        }

        // TBD how to represent handlers for nested fields.
        Dictionary<string /*fieldName*/, FieldHandler> fieldHandlers = new Dictionary<string, FieldHandler>();

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
                    ((SymTTransfer)message.SVX_symT).payloadSecretsVerifiedOnImport.Add(new VerifyOnImportEntry {
                        fieldPath = accessor.name,
                        secretGeneratorTypeFullName = generator.GetType().FullName
                    });
                }
                else
                {
                    generator.ExtractUnverified(secret);
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

        public void Export(TMessage message, PrincipalHandle receiver, PrincipalHandle target)
        {
            foreach (var handler in fieldHandlers.Values)
            {
                handler.Export(message, receiver, target);
            }
        }

        // For cleanliness in serialization, provide a separate API so that
        // message.SVX_directClient is only set when we expect the receiver to
        // use it.
        public void ExportDirectResponse(TMessage message, PrincipalHandle receiver)
        {
            // Factor out a private helper method if necessary in the future.
            Export(message, receiver, null);
            message.SVX_directClient = receiver;
        }

        private void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender, PrincipalHandle realDirectClient)
        {
            // Set up secretsVerifiedOnImport field so Extract can add to it.
            SVX_Ops.Transfer(message, producer, sender, realDirectClient);

            // Extract all fields before importing any, in case getKnownReaders
            // for one secret references information extracted from another
            // field.
            foreach (var handler in fieldHandlers.Values)
            {
                handler.Extract(message);
            }
            foreach (var handler in fieldHandlers.Values)
            {
                handler.Import(message, producer, sender);
            }
        }

        public void Import(TMessage message, PrincipalHandle producer, PrincipalHandle sender)
        {
            Import(message, producer, sender, null);
        }

        // TODO: client needs to tie in to some ambient "current principal" variable
        public void ImportDirectResponse(TMessage message, PrincipalHandle server, PrincipalHandle client)
        {
            Import(message, server, server, client);
        }
    }
}
