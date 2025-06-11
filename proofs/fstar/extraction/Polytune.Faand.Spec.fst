module Polytune.Faand.Spec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

type t_PartyState (v_NUM_PARTIES: usize) (v_NUM_TRIPLES: usize) = {
  f_delta:Polytune.Data_types.t_Delta;
  f_xshares:t_Array Polytune.Data_types.t_Share v_NUM_TRIPLES;
  f_yshares:t_Array Polytune.Data_types.t_Share v_NUM_TRIPLES;
  f_rshares:t_Array Polytune.Data_types.t_Share v_NUM_TRIPLES;
  f_randomness:t_Array bool v_NUM_TRIPLES
}

/// This functions is the global reference for the "leaky authenticated AND" protocol. It computes
/// shares <x>, <y>, and <z> such that the AND of the XORs of the input values x and y equals
/// the XOR of the output values z.
let ideal
      (v_NUM_PARTIES v_NUM_TRIPLES: usize)
      (state_before: t_Array (t_PartyState v_NUM_PARTIES v_NUM_TRIPLES) v_NUM_PARTIES)
    : Alloc.Vec.t_Vec (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
      Alloc.Alloc.t_Global =
  let vis:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      (Alloc.Vec.impl__new #bool () <: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      v_NUM_PARTIES
  in
  let h0h1s:Alloc.Vec.t_Vec
    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
    Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global)
      (Alloc.Vec.impl__new #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) ()
        <:
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      v_NUM_PARTIES
  in
  let h0h1s, vis:(Alloc.Vec.t_Vec
      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_NUM_PARTIES
      (fun temp_0_ temp_1_ ->
          let h0h1s, vis:(Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                vis
              <:
              usize) =.
            v_NUM_PARTIES
            <:
            bool) &&
          ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                h0h1s
              <:
              usize) =.
            v_NUM_PARTIES
            <:
            bool))
      (h0h1s, vis
        <:
        (Alloc.Vec.t_Vec
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
      (fun temp_0_ i ->
          let h0h1s, vis:(Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
            temp_0_
          in
          let i:usize = i in
          let party:t_PartyState v_NUM_PARTIES v_NUM_TRIPLES = state_before.[ i ] in
          let (yi: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global):Alloc.Vec.t_Vec bool
            Alloc.Alloc.t_Global =
            Core.Iter.Traits.Iterator.f_collect #(Core.Iter.Adapters.Map.t_Map
                  (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)
                  (Polytune.Data_types.t_Share -> bool))
              #FStar.Tactics.Typeclasses.solve
              #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
              (Core.Iter.Traits.Iterator.f_map #(Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)
                  #FStar.Tactics.Typeclasses.solve
                  #bool
                  (Core.Slice.impl__iter #Polytune.Data_types.t_Share
                      (party.f_yshares <: t_Slice Polytune.Data_types.t_Share)
                    <:
                    Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)
                  (fun share ->
                      let share:Polytune.Data_types.t_Share = share in
                      share.Polytune.Data_types._0)
                <:
                Core.Iter.Adapters.Map.t_Map (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)
                  (Polytune.Data_types.t_Share -> bool))
          in
          let h0h1:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
            Alloc.Alloc.t_Global =
            Polytune.Faand.fhaand_compute_hashes party.f_delta
              i
              v_NUM_PARTIES
              v_NUM_TRIPLES
              (party.f_xshares <: t_Slice Polytune.Data_types.t_Share)
              yi
              (party.f_randomness <: t_Slice bool)
          in
          let vis:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize vis
              i
              (Rust_primitives.Hax.Monomorphized_update_at.update_at_range_to (vis.[ i ]
                    <:
                    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                  ({ Core.Ops.Range.f_end = v_NUM_TRIPLES } <: Core.Ops.Range.t_RangeTo usize)
                  (Core.Slice.impl__copy_from_slice #bool
                      ((vis.[ i ] <: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global).[ {
                            Core.Ops.Range.f_end = v_NUM_TRIPLES
                          }
                          <:
                          Core.Ops.Range.t_RangeTo usize ]
                        <:
                        t_Slice bool)
                      (party.f_randomness <: t_Slice bool)
                    <:
                    t_Slice bool)
                <:
                Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
          in
          let h0h1s:Alloc.Vec.t_Vec
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1s i h0h1
          in
          h0h1s, vis
          <:
          (Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
  in
  let h0h1_js:Alloc.Vec.t_Vec
    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
    Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global)
      (Alloc.Vec.impl__new #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) ()
        <:
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      v_NUM_PARTIES
  in
  let h0h1_js:Alloc.Vec.t_Vec
    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
    Alloc.Alloc.t_Global =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_NUM_PARTIES
      (fun h0h1_js temp_1_ ->
          let h0h1_js:Alloc.Vec.t_Vec
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
            h0h1_js
          in
          let _:usize = temp_1_ in
          ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                h0h1_js
              <:
              usize) =.
            v_NUM_PARTIES
            <:
            bool) &&
          ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                h0h1s
              <:
              usize) =.
            v_NUM_PARTIES
            <:
            bool))
      h0h1_js
      (fun h0h1_js i ->
          let h0h1_js:Alloc.Vec.t_Vec
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
            h0h1_js
          in
          let i:usize = i in
          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
            v_NUM_PARTIES
            (fun h0h1_js temp_1_ ->
                let h0h1_js:Alloc.Vec.t_Vec
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
                  h0h1_js
                in
                let _:usize = temp_1_ in
                ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                      #Alloc.Alloc.t_Global
                      h0h1_js
                    <:
                    usize) =.
                  v_NUM_PARTIES
                  <:
                  bool) &&
                ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                      #Alloc.Alloc.t_Global
                      h0h1s
                    <:
                    usize) =.
                  v_NUM_PARTIES
                  <:
                  bool))
            h0h1_js
            (fun h0h1_js j ->
                let h0h1_js:Alloc.Vec.t_Vec
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
                  h0h1_js
                in
                let j:usize = j in
                if i =. j <: bool
                then h0h1_js
                else
                  Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1_js
                    i
                    (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (h0h1_js.[ i ]
                          <:
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global)
                        j
                        (Core.Clone.f_clone #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                            #FStar.Tactics.Typeclasses.solve
                            ((h0h1s.[ j ]
                                <:
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global).[ i ]
                              <:
                              Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                          <:
                          Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      <:
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global)
                  <:
                  Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
          <:
          Alloc.Vec.t_Vec
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
  in
  let vis:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      v_NUM_PARTIES
      (fun vis temp_1_ ->
          let vis:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
            vis
          in
          let _:usize = temp_1_ in
          (Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
              #Alloc.Alloc.t_Global
              vis
            <:
            usize) =.
          v_NUM_PARTIES
          <:
          bool)
      vis
      (fun vis i ->
          let vis:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
            vis
          in
          let i:usize = i in
          let party:t_PartyState v_NUM_PARTIES v_NUM_TRIPLES = state_before.[ i ] in
          let vis:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize vis
              i
              (Polytune.Faand.fhaand_compute_vi i
                  v_NUM_PARTIES
                  v_NUM_TRIPLES
                  (party.f_xshares <: t_Slice Polytune.Data_types.t_Share)
                  (vis.[ i ] <: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                  (h0h1_js.[ i ]
                    <:
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global)
                <:
                Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
          in
          vis)
  in
  Rust_primitives.Hax.never_to_any (Core.Panicking.panic "not yet implemented"
      <:
      Rust_primitives.Hax.t_Never)
