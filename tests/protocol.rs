use std::collections::HashSet;

use multi_tandem::{
    circuit::{Circuit, Gate},
    protocol::{simulate_mpc, Error},
};

#[test]
fn eval_xor_circuits() -> Result<(), Error> {
    for x in [true, false] {
        for y in [true, false] {
            for z in [true, false] {
                let circuit = Circuit::new(
                    vec![
                        Gate::InContrib,
                        Gate::InEval,
                        Gate::Xor(0, 1),
                        Gate::InContrib,
                        Gate::Xor(2, 3),
                    ],
                    vec![4],
                );

                let output = simulate_mpc(&circuit, &[x, z], &[y])?;
                assert_eq!(output, vec![None, None, None, None, Some((x ^ y) ^ z)]);
            }
        }
    }
    Ok(())
}

#[test]
fn eval_not_circuits() -> Result<(), Error> {
    for x in [true, false] {
        for y in [true, false] {
            let circuit = Circuit::new(
                vec![
                    Gate::InContrib,
                    Gate::InEval,
                    Gate::Not(0),
                    Gate::Not(1),
                    Gate::Not(2),
                ],
                vec![2, 3, 4],
            );

            let output = simulate_mpc(&circuit, &[x], &[y])?;
            assert_eq!(output, vec![None, None, Some(!x), Some(!y), Some(x)]);
        }
    }
    Ok(())
}

#[test]
fn eval_and_circuits() -> Result<(), Error> {
    for x in [true, false] {
        for y in [true, false] {
            for z in [true, false] {
                let circuit = Circuit::new(
                    vec![
                        Gate::InContrib,
                        Gate::InEval,
                        Gate::And(0, 1),
                        Gate::InContrib,
                        Gate::And(2, 3),
                    ],
                    vec![4],
                );

                let output = simulate_mpc(&circuit, &[x, z], &[y])?;
                assert_eq!(output, vec![None, None, None, None, Some((x & y) & z)]);
            }
        }
    }
    Ok(())
}

#[test]
fn eval_large_and_circuit() -> Result<(), Error> {
    let n = 1_000;
    let mut in_a = vec![];
    let mut in_b = vec![];
    let mut gates = Vec::new();
    for _ in 0..n {
        in_a.push(true);
        gates.push(Gate::InContrib);
    }
    for _ in n..(n * 2) {
        in_b.push(true);
        gates.push(Gate::InEval);
    }
    gates.push(Gate::And(0, 1));
    for w in 2..(n * 2) {
        gates.push(Gate::And(((n * 2) + w - 2) as u32, w as u32));
    }
    let output_gates = vec![(gates.len() - 1) as u32];
    let circuit = Circuit::new(gates, output_gates);
    println!("Circuit: {:?}", circuit);
    println!("A: {:?}", in_a);
    println!("B: {:?}", in_b);

    let mut expected = vec![None; circuit.gates().len()];
    expected[circuit.gates().len() - 1] = Some(true);

    let output_smpc = simulate_mpc(&circuit, &in_a, &in_b)?;
    let output_direct = eval_directly(&circuit, &in_a, &in_b);
    assert_eq!(output_smpc, expected);
    assert_eq!(output_smpc, output_direct);

    Ok(())
}

#[test]
fn eval_mixed_circuits() -> Result<(), Error> {
    let circuits = gen_circuits_up_to(6);
    let mut circuits_with_inputs = Vec::new();
    for circuit in circuits {
        let in_a = circuit.contrib_inputs();
        let in_b = circuit.eval_inputs();
        let mut inputs = vec![(vec![], vec![])];
        for _ in 0..in_a {
            let mut next_round_of_inputs = Vec::new();
            for (inputs_a, inputs_b) in inputs.iter() {
                let mut with_true = inputs_a.clone();
                with_true.push(true);
                next_round_of_inputs.push((with_true, inputs_b.clone()));
                let mut with_false = inputs_a.clone();
                with_false.push(false);
                next_round_of_inputs.push((with_false, inputs_b.clone()));
            }
            inputs.clear();
            inputs.append(&mut next_round_of_inputs);
        }
        for _ in in_a..(in_a + in_b) {
            let mut next_round_of_inputs = Vec::new();
            for (inputs_a, inputs_b) in inputs.iter() {
                let mut with_true = inputs_b.clone();
                with_true.push(true);
                next_round_of_inputs.push((inputs_a.clone(), with_true));
                let mut with_false = inputs_b.clone();
                with_false.push(false);
                next_round_of_inputs.push((inputs_a.clone(), with_false));
            }
            inputs.clear();
            inputs.append(&mut next_round_of_inputs);
        }
        for (a, b) in inputs {
            circuits_with_inputs.push((circuit.clone(), a, b));
        }
    }
    println!("{} combinations generated", circuits_with_inputs.len());

    let eval_only_every_n = 41; // prime, to avoid periodic patterns
    let mut total_tests = 0;
    for (w, (circuit, in_a, in_b)) in circuits_with_inputs.into_iter().enumerate() {
        if w % eval_only_every_n == 0 {
            total_tests += 1;
            let output_smpc = simulate_mpc(&circuit, &in_a, &in_b)?;
            let output_direct = eval_directly(&circuit, &in_a, &in_b);
            if output_smpc != output_direct {
                println!("Circuit: {:?}", circuit);
                println!("A: {:?}", in_a);
                println!("B: {:?}\n", in_b);
                panic!(
                    "Output did not match: {:?} vs {:?}",
                    output_smpc, output_direct
                );
            }
        }
    }
    println!("Successfully ran {} tests", total_tests);
    Ok(())
}

fn eval_directly(circuit: &Circuit, in_a: &[bool], in_b: &[bool]) -> Vec<Option<bool>> {
    let mut output = vec![None; circuit.gates().len()];
    let mut in_a = in_a.iter();
    let mut in_b = in_b.iter();
    for (w, gate) in circuit.gates().iter().enumerate() {
        match gate {
            Gate::InContrib => {
                output[w] = in_a.next().copied();
            }
            Gate::InEval => {
                output[w] = in_b.next().copied();
            }
            Gate::Not(x) => {
                output[w] = Some(!output[*x as usize].unwrap());
            }
            Gate::Xor(x, y) => {
                output[w] = Some(output[*x as usize].unwrap() ^ output[*y as usize].unwrap());
            }
            Gate::And(x, y) => {
                output[w] = Some(output[*x as usize].unwrap() & output[*y as usize].unwrap());
            }
        }
    }
    let output_wires: HashSet<usize> =
        HashSet::from_iter(circuit.output_gates().iter().map(|w| *w as usize));
    for (w, output) in output.iter_mut().enumerate() {
        if !output_wires.contains(&w) {
            *output = None
        }
    }
    output
}

fn gen_circuits_up_to(n: usize) -> Vec<Circuit> {
    let mut circuits_up_to_n = Vec::new();
    for wires in 5..n {
        for in_a in 2..(wires - 1) {
            for in_b in 1..(wires - in_a) {
                let gates = wires - in_a - in_b;
                if gates < in_a + in_b {
                    continue;
                }

                println!(
                    "Generating circuits with {} inputs from A + {} inputs from B + {} gates = {} total",
                    in_a, in_b, gates, wires
                );

                let mut circuit = Vec::new();
                for _w in 0..in_a {
                    circuit.push(Gate::InContrib);
                }
                for _w in in_a..(in_a + in_b) {
                    circuit.push(Gate::InEval);
                }
                let mut circuits = vec![circuit];
                for w in (in_a + in_b)..wires {
                    let mut next_round_of_circuits = Vec::new();
                    for circuit in circuits.iter_mut() {
                        let mut circuits_with_next_gate = Vec::new();
                        for x in 0..w {
                            for y in 0..w {
                                let x = x as u32;
                                let y = y as u32;
                                for gate in [Gate::And(x, y), Gate::Xor(x, y), Gate::Not(x)] {
                                    let mut circuit = circuit.clone();
                                    circuit.push(gate);
                                    circuits_with_next_gate.push(circuit);
                                }
                            }
                        }
                        next_round_of_circuits.append(&mut circuits_with_next_gate);
                    }
                    circuits.clear();
                    circuits.append(&mut next_round_of_circuits);
                }
                for gates in circuits {
                    let mut output_gates = vec![];
                    for (w, gate) in gates.iter().enumerate() {
                        match gate {
                            Gate::InContrib | Gate::InEval => {}
                            Gate::Xor(_, _) | Gate::And(_, _) | Gate::Not(_) => {
                                output_gates.push(w as u32)
                            }
                        }
                    }
                    circuits_up_to_n.push(Circuit::new(gates, output_gates));
                }
            }
        }
    }
    circuits_up_to_n
}
