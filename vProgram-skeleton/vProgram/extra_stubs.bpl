///////////////////////////////////////////////////////////////////////////////
// String concatenation is deterministic.  Used by SVX2_Test example.

function StringConcat(x: Ref, y: Ref) : Ref;

implementation {:inline 1} System.String.Concat$System.String$System.String(str0$in: Ref, str1$in: Ref) returns ($result: Ref)
{
  $result := StringConcat(str0$in, str1$in);
}

///////////////////////////////////////////////////////////////////////////////
// Pretend that PrincipalHandles are interned, like strings.

function Principal.Of(name: Ref) : Ref;
function PrincipalFacet.Of(issuer: Ref, id: Ref) : Ref;

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
function ActsFor(actor: Ref, target: Ref) : bool;
axiom (forall p: Ref :: ActsFor(p, p));
axiom (forall x, y, z: Ref :: {ActsFor(x, y), ActsFor(y, z)} ActsFor(x, y) && ActsFor(y, z) ==> ActsFor(x, z));

implementation SVX2.VProgram_API.UnderlyingPrincipal$SVX2.PrincipalHandle(ph$in: Ref) returns ($result: Ref)
{
  $result := UnderlyingPrincipal(ph$in);
}

implementation SVX2.VProgram_API.ActsFor$SVX2.PrincipalHandle$SVX2.PrincipalHandle(actor$in: Ref, target$in: Ref) returns ($result: bool)
{
  $result := ActsFor(UnderlyingPrincipal(actor$in), UnderlyingPrincipal(target$in));
}
