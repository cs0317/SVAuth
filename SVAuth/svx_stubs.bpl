///////////////////////////////////////////////////////////////////////////////
// String concatenation is deterministic.  Used by SVX_Test_Concat example.

function StringConcat(x: Ref, y: Ref) : Ref;

// Hm, I wonder what triggers Z3 would actually choose by default.
axiom (forall x, y, z: Ref :: {StringConcat(x, StringConcat(y, z))} {StringConcat(StringConcat(x, y), z)}
  StringConcat(x, StringConcat(y, z)) == StringConcat(StringConcat(x, y), z));

// A given program is not guaranteed to reference all of these and cause BCT to
// translate their declarations, so allow these definitions to stand alone.  (In
// other cases, we use "implementation" so Corral gives us an error and we find
// out up front if our implementation doesn't match the intended translated
// declaration.)

procedure {:inline 1} System.String.Concat$System.String$System.String(str0$in: Ref, str1$in: Ref) returns ($result: Ref)
{
  $result := StringConcat(str0$in, str1$in);
}
procedure {:inline 1} System.String.Concat$System.String$System.String$System.String(str0$in: Ref, str1$in: Ref, str2$in: Ref) returns ($result: Ref)
{
  $result := StringConcat(str0$in, StringConcat(str1$in, str2$in));
}
procedure {:inline 1} System.String.Concat$System.String$System.String$System.String$System.String(str0$in: Ref, str1$in: Ref, str2$in: Ref, str3$in: Ref) returns ($result: Ref)
{
  $result := StringConcat(str0$in, StringConcat(str1$in, StringConcat(str2$in, str3$in)));
}

///////////////////////////////////////////////////////////////////////////////
// Principals

// Pretend that Principals are interned, like strings.

// XXX Do we need to actually axiomatize that the principal has the name we asked for?
// That probably requires replacing the public field with a property that we can implement in Boogie.
function Entity.Of(name: Ref) : Ref;
axiom (forall name1, name2: Ref :: Entity.Of(name1) == Entity.Of(name2) ==> name1 == name2);
function Channel.Of(issuer: Ref, id: Ref) : Ref;
axiom (forall issuer1, id1, issuer2, id2: Ref :: Channel.Of(issuer1, id1) == Channel.Of(issuer2, id2) ==> (issuer1 == issuer2 && id1 == id2));

implementation {:inline 1} SVX.Entity.Of$System.String(name$in: Ref) returns ($result: Ref)
{
  $result := Entity.Of(name$in);
}

implementation {:inline 1} SVX.Channel.Of$SVX.Entity$System.String(issuer$in: Ref, id$in: Ref) returns ($result: Ref)
{
  $result := Channel.Of(issuer$in, id$in);
}

implementation {:inline 1} SVX.Principal.op_Equality$SVX.Principal$SVX.Principal(a$in: Ref, b$in: Ref) returns ($result: bool)
{
  $result := (a$in == b$in);
}

implementation {:inline 1} SVX.Principal.op_Inequality$SVX.Principal$SVX.Principal(a$in: Ref, b$in: Ref) returns ($result: bool)
{
  $result := (a$in != b$in);
}

///////////////////////////////////////////////////////////////////////////////
// Acts-for

// Corral should be able to see at runtime that this is assigned a principal, so
// it is its own underlying principal.
// var F$SVX.VProgram_API.trustedPrincipal : Ref;

// We don't care what this returns for Refs that aren't Principals.
function UnderlyingPrincipal(principalHandle: Ref) : Ref;
axiom (forall p: Ref :: $DynamicType(UnderlyingPrincipal(p)) == T$SVX.Entity());
axiom (forall p: Ref :: $DynamicType(p) == T$SVX.Entity() ==> UnderlyingPrincipal(p) == p);

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

implementation SVX.VProgram_API.UnderlyingPrincipal$SVX.Principal(ph$in: Ref) returns ($result: Ref)
{
  $result := UnderlyingPrincipal(ph$in);
}

implementation SVX.VProgram_API.ActsFor$SVX.Principal$SVX.Principal(actor$in: Ref, target$in: Ref) returns ($result: bool)
{
  $result := ActsFor(actor$in, target$in);
}

implementation SVX.VProgram_API.AssumeNoOneElseActsFor$SVX.Principal(ph$in: Ref)
{
  assume (forall actor: Ref :: ActsFor(actor, ph$in) ==> UnderlyingPrincipal(actor) == UnderlyingPrincipal(ph$in));
}

///////////////////////////////////////////////////////////////////////////////
// Tokens

// TODO: Maybe we should actually keep a data structure of what secrets we know
// are valid and/or borne.  It wouldn't be as "pure" as logical assumptions, but
// we could implement it in C# and third-party developers would actually have a
// hope of being able to debug it.

function Borne(bearer: Ref, secretValue: Ref) : bool;

function TokenParams(tokenValue: Ref) : Ref;

implementation SVX.VProgram_API.AssumeBorneImpl$SVX.Principal$System.String(bearer$in: Ref, secretValue$in: Ref)
{
  // Note, secretValue may be null.  This should be harmless.
  assume Borne(bearer$in, secretValue$in);
}

implementation SVX.VProgram_API.AssumeTokenParamsImpl$System.String$System.Object(tokenValue$in: Ref, theParams$in: Ref)
{
  // FIXME: This is unsound if two distinct but equal parameter objects are
  // allocated in C#.  We should be able to get away with this for both the
  // implicit flow (where the payload secret is never taken apart in the
  // vProgram) and the authorization code flow (by nondetting one of the
  // parameter objects). ~ t-mattmc@microsoft.com 2016-07-18
  assume TokenParams(tokenValue$in) == theParams$in;
}

implementation SVX.VProgram_API.AssumeAuthenticatesBearerImpl$System.String$SVX.Principalarray(secretValue$in: Ref, readers$in: Ref)
{
  assume (forall bearer: Ref :: Borne(bearer, secretValue$in) ==>
    // This duplicates the logic of VProgram_API.ActsForAny, but I don't see any
    // way to factor it out because we can't call a procedure inside the forall
    // and a function can't read global variables.
    (exists i: int :: i >= 0 && i < $ArrayLength(readers$in) &&
      (ActsFor(bearer, $ArrayContents[readers$in][i]) || !ActsFor($ArrayContents[readers$in][i], F$SVX.VProgram_API.trustedPrincipal))
      ));
}

///////////////////////////////////////////////////////////////////////////////
// Declarable predicates

function AllDeclarablePredicates1Arg(dp: Ref, arg1: Ref): bool;
function AllDeclarablePredicates2Arg(dp: Ref, arg1: Ref, arg2: Ref): bool;

implementation SVX.DeclarablePredicate`1.Check$`0($this: Ref, arg1$in: Ref) returns ($result: bool)
{
  $result := AllDeclarablePredicates1Arg($this, arg1$in);
}

implementation SVX.DeclarablePredicate`2.Check$`0$`1($this: Ref, arg1$in: Ref, arg2$in: Ref) returns ($result: bool)
{
  $result := AllDeclarablePredicates2Arg($this, arg1$in, arg2$in);
}
