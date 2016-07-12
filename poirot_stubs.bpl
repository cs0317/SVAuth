const hashsetEmpty : [Union]bool;
axiom (forall x: Union :: {hashsetEmpty[x]} !hashsetEmpty[x]);

var hashsets: [Ref][Union]bool;
var hashsetSize: [Ref]int;

procedure {:extern} System.Collections.Generic.HashSet`1.#ctor($this: Ref) 
{
  hashsets[$this] := hashsetEmpty;
  hashsetSize[$this] := 0;
}

procedure {:extern} System.Collections.Generic.HashSet`1.Add$`0($this: Ref, item$in: Union) returns ($result: bool)
{
  $result := !hashsets[$this][item$in];
  hashsets[$this][item$in] := true;
  if ($result) {
    hashsetSize[$this] := hashsetSize[$this] + 1;
  }
}

procedure {:extern} System.Collections.Generic.HashSet`1.Contains$`0($this: Ref, item$in: Union) returns ($result: bool)
{
  $result := hashsets[$this][item$in];
}

procedure {:extern} System.Collections.Generic.HashSet`1.Remove$`0($this: Ref, item$in: Union) returns ($result: bool)
{
  $result := hashsets[$this][item$in];
  hashsets[$this][item$in] := false;
  if ($result) {
    hashsetSize[$this] := hashsetSize[$this] - 1;
  }
}

procedure {:extern} System.Collections.Generic.HashSet`1.get_Count($this: Ref) returns ($result: int)
{
    $result := hashsetSize[$this];
}

procedure {:extern} System.Collections.Generic.HashSet`1.New($this: Ref) returns ($result: Ref)
{
    call $result := Alloc();
    call System.Collections.Generic.HashSet`1.#ctor($result);
    assume $DynamicType($result) == $DynamicType($this);
}

var stacks: [Ref][int]Union;
var stackPtr: [Ref]int;

procedure {:extern} System.Collections.Generic.Stack`1.#ctor($this: Ref)
{
  stackPtr[$this] := 0;
}

procedure {:extern} System.Collections.Generic.Stack`1.Push$`0($this: Ref, item$in: Union)
{
  stacks[$this][stackPtr[$this]] := item$in;
  stackPtr[$this] := stackPtr[$this] + 1;
}

procedure {:extern} System.Collections.Generic.Stack`1.Pop($this: Ref) returns ($result: Union)
{
  stackPtr[$this] := stackPtr[$this] - 1;
  $result := stacks[$this][stackPtr[$this]];
}

procedure {:extern} System.Collections.Generic.Stack`1.get_Count($this: Ref) returns ($result: int)
{
  $result := stackPtr[$this];
}

procedure {:extern} System.Collections.Generic.Stack`1.Peek($this: Ref) returns ($result: Union)
{
  $result := stacks[$this][stackPtr[$this] - 1];
}

var listContents: [Ref][int]Union;
var listSize: [Ref]int;

procedure {:extern} System.Collections.Generic.List`1.#ctor($this: Ref)
{
    listSize[$this] := 0;
}

procedure {:extern} System.Collections.Generic.List`1.Add$`0($this: Ref, item$in: Union)
{
    var size: int;

    size := listSize[$this];
    listContents[$this][size] := item$in;
    listSize[$this] := size + 1;
}

procedure {:extern} System.Collections.Generic.List`1.Remove$`0($this: Ref, item$in: Union) returns ($result: bool)
{
    var iter: int;

    $result := false;
    iter := 0;
    while (iter < listSize[$this] && !$result) {
        $result := (item$in == listContents[$this][iter]);
	iter := iter + 1;
    }

    while (iter < listSize[$this]) {
        listContents[$this][iter-1] := listContents[$this][iter];
	iter := iter + 1;
    }

    if ($result) {
        listSize[$this] := listSize[$this] - 1;
    }
}

procedure {:extern} System.Collections.Generic.List`1.Contains$`0($this: Ref, item$in: Union) returns ($result: bool)
{
    var iter: int;

    $result := false;
    iter := 0;
    while (iter < listSize[$this] && !$result) {
        $result := (item$in == listContents[$this][iter]);
	iter := iter + 1;
    }
}

procedure {:extern} System.Collections.Generic.List`1.get_Count($this: Ref) returns ($result: int)
{
    $result := listSize[$this];
}

procedure {:extern} System.Collections.Generic.List`1.Clear($this: Ref)
{
    listSize[$this] := 0;
}

procedure {:extern} System.Collections.Generic.List`1.get_Item$System.Int32($this: Ref, index$in: int) returns ($result: Union)
{
    $result := listContents[$this][index$in];
}

procedure {:extern} System.Collections.Generic.List`1.set_Item$System.Int32$`0($this: Ref, index$in: int, value$in: Union)
{
    listContents[$this][index$in] := value$in;
}

// We reuse "hashsets" for key presence in dictionaries.
var DictValues: [Ref][Union]Union;

procedure {:extern} System.Collections.Generic.Dictionary`2.#ctor($this: Ref) 
{
    hashsets[$this] := hashsetEmpty;
}

procedure {:extern} System.Collections.Generic.Dictionary`2.get_Item$`0(this: Ref, key$in: Union) returns ($result: Union)
{
    if (hashsets[this][key$in]) {
	    $result := DictValues[this][key$in];
	} else {
        // FIXME: This should throw a KeyNotFoundException.
        $result := null;
	}
}

procedure {:extern} System.Collections.Generic.Dictionary`2.set_Item$`0$`1(this: Ref, key$in: Union, value$in: Union)
{
    hashsets[this][key$in] := true;
    DictValues[this][key$in] := value$in;
}

procedure {:extern} System.Collections.Generic.Dictionary`2.TryGetValue$`0$`1$($this: Ref, key$in: Ref, value$in: Ref) returns (value$out: Ref, $result: bool)
{
    if (hashsets[$this][key$in]) {
        value$out := DictValues[$this][key$in];
        $result := true;
	} else {
        // BCT has axioms that Unbox2T(null) == default(T) for the relevant types T.
        value$out := null;
        $result := false;
	}
}
