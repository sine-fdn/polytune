use garble_lang::{
    circuit::{Circuit, Gate},
    compile,
};
use parlay::protocol::{simulate_mpc, Error};

#[test]
fn eval_xor_circuits_2pc() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![1];
    for x in [true, false] {
        for y in [true, false] {
            for z in [true, false] {
                let circuit = Circuit {
                    input_gates: vec![2, 1],
                    gates: vec![Gate::Xor(0, 2), Gate::Xor(1, 3)],
                    output_gates: vec![4],
                };

                let output = simulate_mpc(&circuit, &[&[x, z], &[y]], &output_parties)?;
                assert_eq!(output, vec![x ^ y ^ z]);
            }
        }
    }
    Ok(())
}

#[test]
fn eval_xor_circuits_3pc() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![1, 2];
    for x in [true, false] {
        for y in [true, false] {
            for z in [true, false] {
                let circuit = Circuit {
                    input_gates: vec![1, 1, 1],
                    gates: vec![Gate::Xor(0, 2), Gate::Xor(1, 3)],
                    output_gates: vec![4],
                };

                let output = simulate_mpc(&circuit, &[&[x], &[y], &[z]], &output_parties)?;
                assert_eq!(output, vec![x ^ y ^ z]);
            }
        }
    }
    Ok(())
}

#[test]
fn eval_not_circuits_2pc() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![1];
    for x in [true, false] {
        for y in [true, false] {
            let circuit = Circuit {
                input_gates: vec![1, 1],
                gates: vec![Gate::Not(0), Gate::Not(1), Gate::Not(2), Gate::Not(3)],
                output_gates: vec![2, 3, 4, 5],
            };

            let output = simulate_mpc(&circuit, &[&[x], &[y]], &output_parties)?;
            assert_eq!(output, vec![!x, !y, x, y]);
        }
    }
    Ok(())
}

#[test]
fn eval_not_circuits_3pc() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![0, 1, 2];
    for x in [true, false] {
        for y in [true, false] {
            for z in [true, false] {
                let circuit = Circuit {
                    input_gates: vec![1, 1, 1],
                    gates: vec![
                        Gate::Not(0),
                        Gate::Not(1),
                        Gate::Not(2),
                        Gate::Not(3),
                        Gate::Not(4),
                        Gate::Not(5),
                    ],
                    output_gates: vec![3, 4, 5, 6, 7, 8],
                };

                let output = simulate_mpc(&circuit, &[&[x], &[y], &[z]], &output_parties)?;
                assert_eq!(output, vec![!x, !y, !z, x, y, z]);
            }
        }
    }
    Ok(())
}

#[test]
fn eval_and_circuits_2pc() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![0, 1];
    for x in [true, false] {
        for y in [true, false] {
            for z in [true, false] {
                let circuit = Circuit {
                    input_gates: vec![2, 1],
                    gates: vec![Gate::And(0, 2), Gate::And(1, 3)],
                    output_gates: vec![4],
                };

                let output = simulate_mpc(&circuit, &[&[x, z], &[y]], &output_parties)?;
                assert_eq!(output, vec![x & y & z]);
            }
        }
    }
    Ok(())
}

//#[test]
fn eval_and_circuits_3pc() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![0, 1, 2];
    for x in [true, false] {
        for y in [true, false] {
            for z in [true, false] {
                let circuit = Circuit {
                    input_gates: vec![1, 1, 1],
                    gates: vec![Gate::And(0, 2), Gate::And(1, 3)],
                    output_gates: vec![4],
                };

                let output = simulate_mpc(&circuit, &[&[x], &[y], &[z]], &output_parties)?;
                assert_eq!(output, vec![x & y & z]);
            }
        }
    }
    Ok(())
}

//#[test]
fn eval_garble_prg_3pc() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![0, 1, 2];
    let prg = compile("pub fn main(x: u8, y: u8, z: u8) -> u8 { x * y * z }").unwrap();
    for x in 0..3 {
        for y in 0..3 {
            for z in 0..3 {
                let expected = x * y * z;
                let calculation = format!("{x}u8 * {y}u8 * {z}u8");
                let x = prg.parse_arg(0, &format!("{x}u8")).unwrap().as_bits();
                let y = prg.parse_arg(1, &format!("{y}u8")).unwrap().as_bits();
                let z = prg.parse_arg(2, &format!("{z}u8")).unwrap().as_bits();
                let output = simulate_mpc(&prg.circuit, &[&x, &y, &z], &output_parties)?;
                let result = prg.parse_output(&output).unwrap();
                println!("{calculation} = {result}");
                assert_eq!(format!("{result}"), format!("{expected}u8"));
            }
        }
    }
    Ok(())
}

#[test]
fn eval_large_and_circuit() -> Result<(), Error> {
    let output_parties: Vec<usize> = vec![0, 1];
    let n = 100;
    let mut in_a = vec![];
    let mut in_b = vec![];
    let mut gates = Vec::new();
    for _ in 0..n {
        in_a.push(true);
    }
    for _ in n..(n * 2) {
        in_b.push(true);
    }
    gates.push(Gate::And(0, 1));
    for w in 2..(n * 2) {
        gates.push(Gate::And((n * 2) + w - 2, w));
    }
    let output_gates = vec![n + n + gates.len() - 1];
    let circuit = Circuit {
        input_gates: vec![n, n],
        gates: gates.clone(),
        output_gates,
    };

    let output_smpc = simulate_mpc(&circuit, &[&in_a, &in_b], &output_parties)?;
    let output_direct = eval_directly(&circuit, &[&in_a, &in_b]);
    assert_eq!(output_smpc, vec![true]);
    assert_eq!(output_smpc, output_direct);

    Ok(())
}

#[test]
fn eval_mixed_circuits() -> Result<(), Error> {
    let circuits = gen_circuits_up_to(5);
    let mut circuits_with_inputs = Vec::new();
    let output_parties: Vec<usize> = vec![0, 1];
    for circuit in circuits {
        let in_a = circuit.input_gates[0];
        let in_b = circuit.input_gates[1];
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

    let eval_only_every_n = 31; // prime, to avoid periodic patterns
    let mut total_tests = 0;
    for (w, (circuit, in_a, in_b)) in circuits_with_inputs.into_iter().enumerate() {
        if w % eval_only_every_n == 0 {
            total_tests += 1;
            let output_smpc = simulate_mpc(&circuit, &[&in_a, &in_b], &output_parties)?;
            let output_direct = eval_directly(&circuit, &[&in_a, &in_b]);
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

fn eval_directly(circuit: &Circuit, inputs: &[&[bool]]) -> Vec<bool> {
    let num_inputs: usize = inputs.iter().map(|inputs| inputs.len()).sum();
    let mut output = vec![None; num_inputs + circuit.gates.len()];
    let mut i = 0;
    for inputs in inputs.iter() {
        for input in inputs.iter() {
            output[i] = Some(*input);
            i += 1;
        }
    }
    for (g, gate) in circuit.gates.iter().enumerate() {
        let w = i + g;
        match gate {
            Gate::Not(x) => {
                output[w] = Some(!output[*x].unwrap());
            }
            Gate::Xor(x, y) => {
                output[w] = Some(output[*x].unwrap() ^ output[*y].unwrap());
            }
            Gate::And(x, y) => {
                output[w] = Some(output[*x].unwrap() & output[*y].unwrap());
            }
        }
    }
    let mut outputs = vec![];
    for w in circuit.output_gates.iter() {
        outputs.push(output[*w].unwrap());
    }
    outputs
}

fn gen_circuits_up_to(n: usize) -> Vec<Circuit> {
    let mut circuits_up_to_n = Vec::new();
    let mut gate_choice = 0;
    for in_a in 1..=(n / 2) {
        for in_b in 1..=(n / 2) {
            for gates in (in_a + in_b)..n {
                let wires = in_a + in_b + gates;
                println!(
                    "Generating circuits with {} inputs from A + {} inputs from B + {} gates = {} total",
                    in_a, in_b, gates, wires
                );
                let mut circuits = vec![vec![]];
                for w in (in_a + in_b)..wires {
                    let mut next_round_of_circuits = Vec::new();
                    for circuit in circuits.iter_mut() {
                        let mut circuits_with_next_gate = Vec::new();
                        for x in (0..w).step_by(3) {
                            for y in (0..w).step_by(2) {
                                gate_choice += 1;
                                let gate = match gate_choice % 7 {
                                    0..=2 => Gate::And(x, y),
                                    3..=5 => Gate::Xor(x, y),
                                    _ => Gate::Not(x),
                                };
                                let mut circuit = circuit.clone();
                                circuit.push(gate);
                                circuits_with_next_gate.push(circuit);
                            }
                        }
                        next_round_of_circuits.append(&mut circuits_with_next_gate);
                    }
                    circuits.clear();
                    circuits.append(&mut next_round_of_circuits);
                }
                for gates in circuits {
                    let mut output_gates = vec![];
                    for w in 0..gates.iter().len() {
                        output_gates.push(in_a + in_b + w);
                    }
                    circuits_up_to_n.push(Circuit {
                        input_gates: vec![in_a, in_b],
                        gates,
                        output_gates,
                    });
                }
            }
        }
    }
    circuits_up_to_n
}
