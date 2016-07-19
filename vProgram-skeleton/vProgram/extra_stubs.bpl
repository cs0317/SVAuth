///////////////////////////////////////////////////////////////////////////////
// String concatenation is deterministic.  Used by SVX2_Test example.

function StringConcat(x: Ref, y: Ref) : Ref;

implementation {:inline 1} System.String.Concat$System.String$System.String(str0$in: Ref, str1$in: Ref) returns ($result: Ref)
{
  $result := StringConcat(str0$in, str1$in);
}

///////////////////////////////////////////////////////////////////////////////
// Pretend that PrincipalHandles are interned, like strings.

// XXX Do we need to actually axiomatize that the principal has the name we asked for?
// That probably requires replacing the public field with a property that we can implement in Boogie.
function Principal.Of(name: Ref) : Ref;
axiom (forall name1, name2: Ref :: Principal.Of(name1) == Principal.Of(name2) ==> name1 == name2);
function PrincipalFacet.Of(issuer: Ref, id: Ref) : Ref;
axiom (forall issuer1, id1, issuer2, id2: Ref :: PrincipalFacet.Of(issuer1, id1) == PrincipalFacet.Of(issuer2, id2) ==> (issuer1 == issuer2 && id1 == id2));

implementation {:inline 1} SVX2.Principal.Of$System.String(name$in: Ref) returns ($result: Ref)
{
  $result := Principal.Of(name$in);
}

implementation {:inline 1} SVX2.PrincipalFacet.Of$SVX2.Principal$System.String(issuer$in: Ref, id$in: Ref) returns ($result: Ref)
{
  $result := PrincipalFacet.Of(issuer$in, id$in);
}

implementation {:inline 1} SVX2.PrincipalHandle.op_Equality$SVX2.PrincipalHandle$SVX2.PrincipalHandle(a$in: Ref, b$in: Ref) returns ($result: bool)
{
  $result := (a$in == b$in);
}

implementation {:inline 1} SVX2.PrincipalHandle.op_Inequality$SVX2.PrincipalHandle$SVX2.PrincipalHandle(a$in: Ref, b$in: Ref) returns ($result: bool)
{
  $result := (a$in != b$in);
}

///////////////////////////////////////////////////////////////////////////////
// Acts-for

// We don't care what this returns for Refs that aren't PrincipalHandles.
function UnderlyingPrincipal(principalHandle: Ref) : Ref;
axiom (forall p: Ref :: $DynamicType(UnderlyingPrincipal(p)) == T$SVX2.Principal());
axiom (forall p: Ref :: $DynamicType(p) == T$SVX2.Principal() ==> UnderlyingPrincipal(p) == p);

// Meaningful for principals only.  Note, we do not assume antisymmetry.
//
// The Boogie partial order (<:) is not supported in monomorphic type encoding
// mode, which Corral uses.  But it looks like Boogie is just axiomatizing the
// order and isn't doing anything we can't do for ourselves here.
// https://github.com/boogie-org/boogie/blob/87e1e7b34261eac35869e6eff83fa57ca6268f3d/Source/VCGeneration/OrderingAxioms.cs#L157
function PrincipalActsFor(actor: Ref, target: Ref) : bool;
axiom (forall p: Ref :: PrincipalActsFor(p, p));
axiom (forall x, y, z: Ref :: {PrincipalActsFor(x, y), PrincipalActsFor(y, z)}
  PrincipalActsFor(x, y) && PrincipalActsFor(y, z) ==> PrincipalActsFor(x, z));

function ActsFor(actorHandle: Ref, targetHandle: Ref) : bool {
  PrincipalActsFor(UnderlyingPrincipal(actorHandle), UnderlyingPrincipal(targetHandle))
}

implementation SVX2.VProgram_API.UnderlyingPrincipal$SVX2.PrincipalHandle(ph$in: Ref) returns ($result: Ref)
{
  $result := UnderlyingPrincipal(ph$in);
}

implementation SVX2.VProgram_API.ActsFor$SVX2.PrincipalHandle$SVX2.PrincipalHandle(actor$in: Ref, target$in: Ref) returns ($result: bool)
{
  $result := ActsFor(actor$in, target$in);
}

///////////////////////////////////////////////////////////////////////////////
// Secrets

// TODO: Maybe we should actually keep a data structure of what secrets we know
// are valid and/or borne.  It wouldn't be as "pure" as logical assumptions, but
// we could implement it in C# and third-party developers would actually have a
// hope of being able to debug it.

function Borne(bearer: Ref, secretValue: Ref) : bool;

function SecretParams(secretValue: Ref) : Ref;

implementation SVX2.VProgram_API.AssumeBorneImpl$SVX2.PrincipalHandle$System.String(bearer$in: Ref, secretValue$in: Ref)
{
  // Note, secretValue may be null.  This should be harmless.
  assume Borne(bearer$in, secretValue$in);
}

implementation SVX2.VProgram_API.AssumeValidSecretImpl$System.String$System.Object$SVX2.PrincipalHandlearray(secretValue$in: Ref, theParams$in: Ref, readers$in: Ref)
{
  // FIXME: This is unsound if two distinct but equal parameter objects are
  // allocated in C#.  We should be able to get away with this for both the
  // implicit flow (where the payload secret is never taken apart in the
  // vProgram) and the authorization code flow (by nondetting one of the
  // parameter objects). ~ t-mattmc@microsoft.com 2016-07-18
  assume SecretParams(secretValue$in) == theParams$in;
  assume (forall bearer: Ref :: Borne(bearer, secretValue$in) ==>
    // This duplicates the logic of VProgram_API.ActsForAny, but I don't see any
    // way to factor it out because we can't call a procedure inside the forall
    // and a function can't read global variables.
    (exists i: int :: i >= 0 && i < $ArrayLength(readers$in) && ActsFor(bearer, $ArrayContents[readers$in][i])));
}
