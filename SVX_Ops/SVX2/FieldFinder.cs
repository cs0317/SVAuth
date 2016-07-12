using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace SVX2
{
    // The interface of this class may change as our needs change...
    static class FieldFinder<TNeedle>
    {
        private static HashSet<Type> leafTypes = new HashSet<Type> { typeof(string) };

        internal class Accessor
        {
            // XXX readonly?
            internal string name;
            // I tried adding a type parameter for the message type, but all
            // current callers have only a Type anyway, so it wasn't worth it.
            // ~ t-mattmc@microsoft.com 2016-07-08
            internal Func<object, TNeedle> getter;
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
                        name = fieldInfo.Name,
                        getter = (msg) => (TNeedle)fieldInfo.GetValue(msg),
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
                            name = fieldInfo.Name + "." + nestedFieldAccessor.name,
                            getter = (msg) => nestedFieldAccessor.getter(fieldInfo.GetValue(msg)),
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
