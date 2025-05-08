#[cfg(not(feature = "is_sync"))]
mod tests {
    use garble_lang::{
        circuit::{Circuit, Gate},
        compile,
    };
    use polytune::{
        channel,
        protocol::{mpc, Error},
    };

    /// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
    fn simulate_mpc(
        circuit: &Circuit,
        inputs: &[&[bool]],
        output_parties: &[usize],
    ) -> Result<Vec<bool>, Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("Could not start tokio runtime");
        rt.block_on(simulate_mpc_async(circuit, inputs, output_parties))
    }

    /// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
    async fn simulate_mpc_async(
        circuit: &Circuit,
        inputs: &[&[bool]],
        output_parties: &[usize],
    ) -> Result<Vec<bool>, Error> {
        let p_eval = 0;

        let channels = channel::SimpleChannel::channels(inputs.len());

        let mut parties = channels.into_iter().zip(inputs).enumerate();
        let Some((_, (mut eval_channel, inputs))) = parties.next() else {
            return Ok(vec![]);
        };

        let mut computation: tokio::task::JoinSet<Vec<bool>> = tokio::task::JoinSet::new();
        for (p_own, (mut channel, inputs)) in parties {
            let circuit = circuit.clone();
            let inputs = inputs.to_vec();
            let output_parties = output_parties.to_vec();
            computation.spawn(async move {
                match mpc(
                    &mut channel,
                    &circuit,
                    &inputs,
                    p_eval,
                    p_own,
                    &output_parties,
                )
                .await
                {
                    Ok(res) => {
                        println!(
                            "Party {p_own} sent {:.2}MB of messages",
                            channel.bytes_sent as f64 / 1024.0 / 1024.0
                        );
                        res
                    }
                    Err(e) => {
                        eprintln!("SMPC protocol failed for party {p_own}: {:?}", e);
                        vec![]
                    }
                }
            });
        }
        let eval_result = mpc(
            &mut eval_channel,
            circuit,
            inputs,
            p_eval,
            p_eval,
            output_parties,
        )
        .await;
        match eval_result {
            Err(e) => {
                eprintln!("SMPC protocol failed for Evaluator: {:?}", e);
                Ok(vec![])
            }
            Ok(res) => {
                let mut outputs = vec![res];
                while let Some(output) = computation.join_next().await {
                    if let Ok(output) = output {
                        outputs.push(output);
                    }
                }
                outputs.retain(|o| !o.is_empty());
                if !outputs.windows(2).all(|w| w[0] == w[1]) {
                    eprintln!("The result does not match for all output parties: {outputs:?}");
                }
                let mb = eval_channel.bytes_sent as f64 / 1024.0 / 1024.0;
                println!("Party {p_eval} sent {mb:.2}MB of messages");
                println!("MPC simulation finished successfully!");
                Ok(outputs.pop().unwrap_or_default())
            }
        }
    }

    /// Tests the evaluation of a simple XOR circuit in a two-party computation (2PC) setting.
    ///
    /// This function simulates secure multi-party computation (MPC) where two parties jointly
    /// compute the XOR of their respective inputs without revealing them. Party 1 learns the result,
    /// as defined by the `output_parties` vector. The test verifies if the result matches the
    /// expected output for all possible boolean combinations of inputs `x`, `y`, and `z`.
    ///
    /// # Circuit
    /// - The circuit has 3 inputs, `x` and `z` from party 0 and `y` from party 1.
    /// - The circuit consists of two XOR gates:
    ///   1. The first gate computes `x ^ z`.
    ///   2. The second gate computes `(x ^ z) ^ y`.
    /// - The output gate contains the final result `x ^ y ^ z`.
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

    /// Tests the evaluation of an XOR circuit in a three-party computation (3PC) setting.
    ///
    /// This function simulates secure multi-party computation (MPC) where three parties compute
    /// the XOR of their respective inputs without revealing them. Parties 1 and 2 learn the result,
    /// as defined by the `output_parties` vector. The test verifies if the output matches the
    /// expected result for all possible boolean combinations of inputs `x`, `y`, and `z`.
    ///
    /// # Circuit
    /// - The circuit has 3 inputs: `x` from party 0, `y` from party 1, and `z` from party 2.
    /// - The circuit consists of two XOR gates:
    ///   1. The first gate computes `x ^ z`.
    ///   2. The second gate computes `(x ^ z) ^ y`.
    /// - The final output gate contains the result `x ^ y ^ z`.
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

    /// Tests the evaluation of a NOT circuit in a two-party computation (2PC) setting.
    ///
    /// This function simulates secure multi-party computation (MPC) where two parties compute
    /// NOT operations on their respective inputs without revealing them. Party 1 learns the result,
    /// as defined by the `output_parties` vector. The test verifies if the output matches the
    /// expected negated and original values for inputs `x` and `y` across all possible boolean
    /// combinations.
    ///
    /// # Circuit
    /// - The circuit has 2 inputs: `x` from party 0 and `y` from party 1.
    /// - The circuit consists of four NOT gates:
    ///   1. The first gate negates `x`.
    ///   2. The second gate negates `y`.
    ///   3. The third gate returns the original value of `x` through double negation.
    ///   4. The fourth gate returns the original value of `y` through double negation.
    /// - The final output gates contain the values `[!x, !y, x, y]`.
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

    /// Tests the evaluation of a NOT circuit in a three-party computation (3PC) setting.
    ///
    /// This function simulates secure multi-party computation (MPC) where three parties compute
    /// NOT operations on their respective inputs without revealing them to each other. All parties
    /// learn the result, as defined by the `output_parties` vector. The test verifies if the
    /// output matches the expected negated and original values for inputs `x`, `y`, and `z`
    /// across all boolean combinations.
    ///
    /// # Circuit
    /// - The circuit has 3 inputs: `x` from party 0, `y` from party 1, and `z` from party 2.
    /// - The circuit consists of six NOT gates:
    ///   1. The first three negate the inputs `x`, `y`, and `z`.
    ///   2. The next three return the original values of `x`, `y`, and `z` through double negation.
    /// - The final output gates contain both negated and original values: `[!x, !y, !z, x, y, z]`.
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

    /// Tests the evaluation of an AND circuit in a two-party computation (2PC) setting.
    ///
    /// This function simulates secure multi-party computation (MPC) where two parties compute
    /// the AND operation on their respective inputs. Both parties learn the result,
    /// as defined by the `output_parties` vector. The test verifies if the output matches the
    /// expected result for all possible boolean combinations of inputs `x`, `y`, and `z`.
    ///
    /// # Circuit
    /// - The circuit has 3 inputs: `x` and `z` from party 0, and `y` from party 1.
    /// - The circuit consists of two AND gates:
    ///   1. The first gate computes `x & z`.
    ///   2. The second gate computes `(x & z) & y`.
    /// - The final output gate contains the result `x & y & z`.
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

    /// Tests the evaluation of an AND circuit in a three-party computation (3PC) setting.
    ///
    /// This function simulates secure multi-party computation (MPC) where three parties compute
    /// the AND operation on their respective inputs. All parties learn the result,
    /// as defined by the `output_parties` vector. The test verifies if the output matches the
    /// expected result for all possible boolean combinations of inputs `x`, `y`, and `z`.
    ///
    /// # Circuit
    /// - The circuit has 3 inputs: `x` from party 0, `y` from party 1, and `z` from party 2.
    /// - The circuit consists of two AND gates:
    ///   1. The first gate computes `x & z`.
    ///   2. The second gate computes `(x & z) & y`.
    /// - The final output gate contains the result `x & y & z`.
    #[test]
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

    /// Tests the evaluation of a garble program in a three-party computation (3PC) setting.
    ///
    /// This function simulates secure multi-party computation (MPC) where three parties evaluate
    /// a garble program on all possible combinations of inputs `x`, `y`, and `z`. The output is
    /// revealed to all three parties, as defined by the `output_parties` vector The test checks
    /// if the computed result matches the expected output for the given inputs.
    ///
    /// # Garble Program
    /// - The garble program has 3 inputs: `x` from party 0, `y` from party 1, and `z` from party 2.
    /// - The program consists of a single function `main(x: u8, y: u8, z: u8) -> u8` that computes
    ///   the product of the inputs `x`, `y`, and `z`.
    #[test]
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
                    assert_eq!(format!("{result}"), format!("{expected}"));
                }
            }
        }
        Ok(())
    }

    /// Tests the evaluation of a large dynamic AND circuit in a multi-party computation (MPC) setting.
    ///
    /// This function dynamically generates a large AND circuit with a configurable number of parties
    /// and AND gates. It simulates the MPC evaluation of the circuit and compares the result with a
    /// direct evaluation to ensure correctness. The circuit applies a series of AND operations across
    /// multiple parties' inputs.
    ///
    /// # Circuit
    /// - All inputs are boolean vectors, with each party providing a vector of boolean values, set to random.
    /// - The circuit is created based on the number of parties and AND gates.
    ///   1. The first AND gate computes the AND of the first two inputs.
    ///   2. Each subsequent AND gate computes the AND of previous outputs with the next input.
    /// - The final output is the cumulative AND result of all inputs and is revealed to the first two parties.
    ///
    /// # Arguments
    /// - `num_parties`: The number of parties involved in the computation.
    /// - `num_and_gates`: The number of AND gates in the circuit, distributed across the parties.
    ///
    /// # Example
    /// This test runs with 2 parties and 100 AND gates.
    #[test]
    fn eval_large_and_circuit_dynamic() -> Result<(), Error> {
        fn run_test(num_parties: usize, num_and_gates: usize) -> Result<(), Error> {
            let output_parties: Vec<usize> = vec![0, 1];
            let input_len = (num_and_gates as f32 / num_parties as f32).ceil() as usize;

            let inputs = vec![vec![true; input_len]; num_parties];
            let input_refs: Vec<&[bool]> = inputs.iter().map(|v| v.as_slice()).collect();
            let mut gates = Vec::new();

            gates.push(Gate::And(0, 1));
            for w in 2..(input_len * num_parties) {
                gates.push(Gate::And(w, input_len * num_parties + w - 2));
            }

            let output_gates = vec![input_len * num_parties + gates.len() - 1];
            let circuit = Circuit {
                input_gates: vec![input_len; num_parties],
                gates: gates.clone(),
                output_gates,
            };
            let output_smpc = simulate_mpc(&circuit, &input_refs, &output_parties)?;
            let output_direct = eval_directly(&circuit, &input_refs);
            assert_eq!(output_smpc, output_direct);

            Ok(())
        }
        run_test(2, 100)?;
        Ok(())
    }

    /// Tests the evaluation of various mixed circuits in a multi-party computation (MPC) setting.
    ///
    /// This function generates a set of circuits up to a size of 5, then iterates over all possible
    /// input combinations. The test simulates the evaluation of circuits using MPC and compares
    /// the result to a direct evaluation of the circuit. The result is revealed to both parties.
    ///
    /// # Circuit
    /// - For each circuit, all combinations of boolean inputs are generated for `input_gates[0]` and
    ///   `input_gates[1]`.
    /// - The circuits are generated using the `gen_circuits_up_to(5)` function, which produces a
    ///   variety of circuits with different gate configurations (e.g., AND, NOT, XOR).
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

    /// Directly evaluates a given circuit with the provided boolean inputs.
    ///
    /// This function simulates the evaluation of a circuit by sequentially applying the logic gates
    /// specified in the circuit structure (`AND`, `XOR`, `NOT`) to the given boolean inputs. It returns
    /// the output values for the specified output gates after completing the evaluation.
    ///
    /// # Arguments
    /// - `circuit`: A reference to the `Circuit` object that defines the input gates, logic gates, and output gates.
    /// - `inputs`: A slice of boolean slices, where each slice represents the inputs for each party.
    ///   Each element corresponds to a particular party's inputs for the circuit.
    ///
    /// # Returns
    /// - A `Vec<bool>` containing the boolean results for the specified output gates of the circuit.
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

    /// Generates circuits with varying numbers of inputs from two parties and gates up to a specified size.
    ///
    /// This function creates circuits consisting of different configurations of input gates and logical
    /// gates (`AND`, `XOR`, and `NOT`). It explores combinations of inputs and gates up to the specified
    /// limit `n`, producing circuits that can be used for testing and evaluation in two-party computation
    /// scenarios.
    ///
    /// # Arguments
    /// - `n`: The maximum total number of gates and inputs (for inputs from both parties) to generate circuits.
    ///
    /// # Returns
    /// - A `Vec<Circuit>` containing all generated circuits, each represented by its input gates, gates,
    ///   and output gates.
    ///
    /// # Circuit
    /// - The function iterates through combinations of input counts for two parties and
    ///   calculates the total number of gates based on the provided input sizes.
    /// - For each configuration, it generates circuits by creating a series of logical gates.
    /// - The gates are chosen based on a cyclic pattern, alternating between `AND`, `XOR`, and `NOT` gates.
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
}
