using Newtonsoft.Json;

namespace SVX
{
    public class SVX_MSG
    {
        // For now, none of the real IdPs support SVX, so we don't want to
        // actually send these fields to them.
        // NOTE: This is a behavior change for Facebook
        // marshalCreateAuthorizationRequest, but should be OK.
        // ~ Matt 2016-06-01
        [JsonIgnore]
        public string SymT = "";
        [JsonIgnore]
        public string SignedBy = "";
    }
}
