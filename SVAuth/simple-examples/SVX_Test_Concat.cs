using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;
using SVX;

namespace SVAuth
{
    public class SVX_Test_Concat : Participant
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

        public SVX_Test_Concat(Entity principal) : base(principal) { }

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
        public Concat3Response AssumeProducerActsForAlice(Concat3Response x)
        {
            // For testing.  Wanted: a cleaner way to get this into the SymT!
            VProgram_API.AssumeActsFor(x.SVX_producer, Entity.Of("Carol"));
            VProgram_API.AssumeActsFor(Entity.Of("Carol"), Entity.Of("Alice"));
            return x;
        }
        public bool Predicate(Concat3Response resp) {
            VProgram_API.AssumeTrusted(Entity.Of("Alice"));
            var tmp = resp.first + resp.second;
            var expected = tmp + resp.third;
            return expected == resp.output;
        }
        [BCTOmitImplementation]
        public static void Test()
        {
            var alice = Entity.Of("Alice");
            var bob = Entity.Of("Bob");
            var p = new SVX_Test_Concat(alice);

            var req1 = new Concat2Request("A", "B");
            var resp1 = SVX_Ops.Call(p.Concat2, req1);
            var req2 = new Concat2Request(resp1.output, "C");
            var resp2 = SVX_Ops.Call(p.Concat2, req2);
            var chainResp = SVX_Ops.Call(p.Chain, resp1, resp2);

            var producer = Channel.GenerateNew(bob);
            var sender = Channel.GenerateNew(bob);
            SVX_Ops.TransferForTesting(chainResp, producer, sender);

            // Demonstrate that we can assume acts-for relationships and that
            // we've axiomatized that acts-for is transitive.  Of course, the
            // acts-for relationships in this example do not represent the ones
            // we would assume in any real protocol.
            var respWithAssumption = SVX_Ops.Call(p.AssumeProducerActsForAlice, chainResp);

            SVX_Ops.Certify(respWithAssumption, p.Predicate);
        }
    }
}
