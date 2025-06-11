module Spec.Utils
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul
open Polytune.Data_types
open Polytune.Faand.Spec


let share_bit (share: t_Share) = 
  match share with
    | Share b _auth -> b

val party_state: 
  (#num_parties: usize{v num_parties >= 3}) 
  -> (#num_triples: usize)
  -> t_Array (t_PartyState num_parties num_triples) num_parties
  -> (party: nat{ party < 3 })
  -> t_PartyState num_parties num_triples

let party_state state party = Seq.Base.index state party


val x_bit: 
  (#num_parties: usize{ v num_parties >= 3 })
  -> (#num_triples: usize{ v num_triples >= 1})
  -> t_Array (t_PartyState num_parties num_triples) num_parties
  -> (party: nat{ party < 3})
  -> bool

/// Retrieve the bit of the first xshare from the given party in state
let x_bit state party
          = 
          let party_state = Seq.Base.index state party in
          let zeroeth_share = Seq.Base.index party_state.f_xshares 0 in
            share_bit zeroeth_share

val y_bit: 
  (#num_parties: usize{ v num_parties >= 3 })
  -> (#num_triples: usize{ v num_triples >= 1})
  -> t_Array (t_PartyState num_parties num_triples) num_parties
  -> (party: nat{ party < 3})
  -> bool
  
/// Retrieve the bit of the first xshare from the given party in state
let y_bit state party
          = 
          let party_state = Seq.Base.index state party in
          let zeroeth_share = Seq.Base.index party_state.f_yshares 0 in
            share_bit zeroeth_share

open FStar.List.Tot.Base

val x_bits:
    (#num_parties: usize{ v num_parties >= 3 })
    -> (#num_triples: usize{ v num_triples >= 1})
    -> t_Array (t_PartyState num_parties num_triples) num_parties
    -> list bool

let x_bits state = List.Tot.Base.map (fun (party: nat{ party < 3}) -> x_bit state party) [0;1;2]

val y_bits:
    (#num_parties: usize{ v num_parties >= 3 })
    -> (#num_triples: usize{ v num_triples >= 1})
    -> t_Array (t_PartyState num_parties num_triples) num_parties
    -> list bool
let y_bits state = List.Tot.Base.map (fun (party: nat{ party < 3}) -> y_bit state party) [0;1;2]

val xor_bits: list bool -> bool
let xor_bits = List.Tot.Base.fold_left (fun bit acc -> bit <> acc) false

val and_inputs:
  (#num_parties: usize{ v num_parties >= 3 })
  -> (#num_triples: usize{ v num_triples >= 1})
  -> t_Array (t_PartyState num_parties num_triples) num_parties
  -> Prims.bool

let and_inputs state =
  let x = xor_bits (x_bits state) in
  let y = xor_bits (y_bits state) in
  x && y

type party_states (#num_parties: usize{ v num_parties >= 3 }) (#num_triples: usize{ v num_triples >= 1}) = t_Array (t_PartyState num_parties num_triples) num_parties

type share_vec_aux = Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global
type share_vec = (vec: share_vec_aux{ Seq.Base.length vec > 0 })
type output_shares = Alloc.Vec.t_Vec 
  share_vec
  Alloc.Alloc.t_Global

val first_share: (vec: Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global{ Seq.Base.length vec > 0 }) -> Polytune.Data_types.t_Share
let first_share vec = Seq.Base.index vec 0

val combine_outputs: Alloc.Vec.t_Vec (vec: Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global{ Seq.Base.length vec > 0 })
      Alloc.Alloc.t_Global -> bool
let combine_outputs outputs = xor_bits (List.Tot.Base.map (fun vec -> share_bit (first_share vec)) (Rust_primitives.Arrays.to_list outputs))

val lemma_correctness_first_share 
  (#num_parties: usize{ v num_parties >= 3 })
  (#num_triples: usize{ v num_triples >= 1 })
  (state_before: t_Array (t_PartyState num_parties num_triples) num_parties):
  Lemma (requires True)
        (ensures and_inputs state_before == combine_outputs (ideal num_parties num_triples state_before))
