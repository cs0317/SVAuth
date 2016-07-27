using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace SVX
{
    [BCTOmit]
    public class FieldAccessor<TObject, TField>
    {
        // In case anyone wants this...
        public readonly FieldInfo fieldInfo;

        public string name => fieldInfo.Name;

        internal FieldAccessor(FieldInfo fieldInfo)
        {
            this.fieldInfo = fieldInfo;
        }

        public TField Get(TObject obj)
        {
            return (TField)fieldInfo.GetValue(obj);
        }

        // TBD whether we allow fields to be looked up as supertypes so this does a dynamic cast.
        public void Set(TObject obj, TField value)
        {
            fieldInfo.SetValue(obj, value);
        }
    }

    [BCTOmit]
    public static class FieldLookup
    {
        public static FieldAccessor<TObject, TField> Lookup<TObject, TField>(string name)
        {
            var fieldInfo = typeof(TObject).GetField(name, BindingFlags.Public | BindingFlags.Instance);
            if (fieldInfo.FieldType != typeof(TField))
                throw new ArgumentException();
            return new FieldAccessor<TObject, TField>(fieldInfo);
        }
    }

    // TODO: Merge both Accessor classes.  I'm being sloppy at the moment.

    // The interface of this class may change as our needs change...
    [BCTOmit]
    static class FieldFinder<TNeedle>
    {
        private static HashSet<Type> leafTypes = new HashSet<Type> { typeof(string) };

        internal class Accessor
        {
            // XXX readonly?
            internal string path;
            // I tried adding a type parameter for the message type, but all
            // current callers have only a Type anyway, so it wasn't worth it.
            // ~ t-mattmc@microsoft.com 2016-07-08
            internal Func<object, TNeedle> nullConditionalGetter;
            internal Action<object, TNeedle> setter;
        }

        private static IEnumerable<Accessor> FindFieldsImpl(Type messageType)
        {
            foreach (var fieldInfo in messageType.GetFields(BindingFlags.Instance | BindingFlags.Public))
            {
                Type fieldType = fieldInfo.FieldType;
                if (typeof(TNeedle).IsAssignableFrom(fieldType))
                    yield return new Accessor
                    {
                        path = fieldInfo.Name,
                        nullConditionalGetter = (msg) => (TNeedle)fieldInfo.GetValue(msg),
                        setter = (msg, value) => fieldInfo.SetValue(msg, value)
                    };
                else if (fieldType.GetTypeInfo().IsPrimitive || fieldType.IsArray || leafTypes.Contains(fieldType))
                {
                    // Don't look inside.
                }
                else
                {
                    // For now, we look inside everything else.
                    foreach (var nestedFieldAccessor in FindFields(fieldType))
                        yield return new Accessor
                        {
                            path = fieldInfo.Name + "." + nestedFieldAccessor.path,
                            nullConditionalGetter = (msg) => {
                                var value1 = fieldInfo.GetValue(msg);
                                // default(TNeedle)... is that right or do we just want "where TNeedle : class"?
                                return value1 == null ? default(TNeedle) : nestedFieldAccessor.nullConditionalGetter(value1);
                            },
                            setter = (msg, value) => nestedFieldAccessor.setter(fieldInfo.GetValue(msg), value),
                        };
                }
            }
        }

        static Dictionary<Type, IList<Accessor>> cache = new Dictionary<Type, IList<Accessor>>();

        internal static IEnumerable<Accessor> FindFields(Type messageType)
        {
            IList<Accessor> ret;
            if (!cache.TryGetValue(messageType, out ret))
            {
                ret = FindFieldsImpl(messageType).ToList().AsReadOnly();
                cache.Add(messageType, ret);
            }
            return ret;
        }
    }
}
