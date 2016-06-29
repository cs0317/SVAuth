using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;
using SVX2;

namespace SVAuth
{
    public class Concat2Request
    {
        public string first, second;
        public Concat2Request(string first, string second)
        {
            this.first = first;
            this.second = second;
        }
    }
    public class Concat2Response
    {
        public string first, second, output;
    }
    public class Concat3Response
    {
        public string first, second, third, output;
    }
    public class SVX2_Test : SVX2.Participant
    {
        public string SVXParticipantId => "TestParty";

        // This is going to be an SVX method.
        public Concat2Response Concat2(Concat2Request req)
        {
            var resp = new Concat2Response();
            resp.first = req.first;
            resp.second = req.second;
            resp.output = req.first + req.second;
            return resp;
        }
        public Concat3Response Chain(Concat2Response part1, Concat2Response part2)
        {
            if (part1.output != part2.first)
                throw new ArgumentException();
            var resp = new Concat3Response();
            resp.first = part1.first;
            resp.second = part1.second;
            resp.third = part2.second;
            resp.output = part2.output;
            return resp;
        }
        public static bool Predicate(Concat3Response resp) {
            var tmp = resp.first + resp.second;
            var expected = tmp + resp.third;
            return expected == resp.output;
        }
        public static void Test()
        {
            var p = new SVX2_Test();

            var req1 = new SVX_MSG<Concat2Request>(new Concat2Request("A", "B"));
            var resp1 = SVX_Ops.Call(p.Concat2, req1);
            var req2 = new SVX_MSG<Concat2Request>(new Concat2Request(resp1.Get().output, "C"));
            var resp2 = SVX_Ops.Call(p.Concat2, req2);
            var chainResp = SVX_Ops.Call(p.Chain, resp1, resp2);
            SVX_Ops.Certify(chainResp, Predicate);
        }
    }
}
