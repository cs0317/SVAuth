using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;
using SVX2;

namespace SVAuth
{
    public class Concat2Request : SVX_MSG
    {
        public string first, second;
        public Concat2Request(string first, string second)
        {
            this.first = first;
            this.second = second;
        }
    }
    public class Concat2Response : SVX_MSG
    {
        public string first, second, output;
    }
    public class Concat3Response : SVX_MSG
    {
        public string first, second, third, output;
    }
    public class SVX2_Test : Participant
    {
        public Principal SVXPrincipal => Principal.Of("Alice");

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
        [BCTOmitImplementation]
        public static void Test()
        {
            var p = new SVX2_Test();
            var bob = Principal.Of("Bob");

            var req1 = new Concat2Request("A", "B");
            var resp1 = SVX_Ops.Call(p.Concat2, req1);
            var req2 = new Concat2Request(resp1.output, "C");
            var resp2 = SVX_Ops.Call(p.Concat2, req2);
            var chainResp = SVX_Ops.Call(p.Chain, resp1, resp2);

            var producer = bob;  // imagine the message was signed
            var sender = PrincipalFacet.GenerateNew(bob);
            SVX_Ops.Transfer(chainResp, producer, sender);
            SVX_Ops.Certify(chainResp, Predicate, new Principal[] { bob });
        }
    }
}
