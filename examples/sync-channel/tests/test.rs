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

#[cfg(feature = "is_sync")]
#[cfg(test)]
mod tests {
    use polytune::{
        garble_lang::compile,
        protocol::{mpc, Error},
    };
    use polytune_sync_channel::SimpleSyncChannel;

    #[test]
    fn eval_garble_prg_3pc() -> Result<(), Error> {
        let prg = compile("pub fn main(x: u8, y: u8, z: u8) -> u8 { x * y * z }").unwrap();
        for x in 0..3 {
            for y in 0..3 {
                for z in 0..3 {
                    let expected = x * y * z;
                    let calculation = format!("{x}u8 * {y}u8 * {z}u8");
                    let x = prg.parse_arg(0, &format!("{x}u8")).unwrap().as_bits();
                    let y = prg.parse_arg(1, &format!("{y}u8")).unwrap().as_bits();
                    let z = prg.parse_arg(2, &format!("{z}u8")).unwrap().as_bits();
                    let inputs = [&x, &y, &z];

                    let channels = SimpleSyncChannel::channels(inputs.len());
                    let p_eval = 0;
                    let p_out: Vec<usize> = vec![0, 1, 2];

                    let mut parties = channels.into_iter().zip(inputs).enumerate();
                    let evaluator = parties.next().unwrap();

                    let mut computation_threads = vec![];
                    for (p_own, (mut ch, inputs)) in parties {
                        let circuit = prg.circuit.clone();
                        let inputs = inputs.to_vec();
                        let p_out = p_out.clone();
                        let handle = std::thread::spawn(move || {
                            let out = mpc(&mut ch, &circuit, &inputs, p_eval, p_own, &p_out);
                            match out {
                                Err(e) => Err(e),
                                Ok(res) => Ok(res),
                            }
                        });
                        computation_threads.push(handle);
                    }

                    let (_, (mut ch, inputs)) = evaluator;
                    let circuit = &prg.circuit;
                    let out = mpc(&mut ch, &circuit, inputs, p_eval, p_eval, &p_out).unwrap();

                    let mut outputs = vec![out];
                    for handle in computation_threads {
                        match handle.join().unwrap() {
                            Ok(output) if !output.is_empty() => outputs.push(output),
                            Ok(_) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    outputs.retain(|o| !o.is_empty());
                    if !outputs.windows(2).all(|w| w[0] == w[1]) {
                        eprintln!("The result does not match for all output parties: {outputs:?}");
                    }
                    let mb = ch.bytes_sent as f64 / 1024.0 / 1024.0;
                    println!("Party {p_eval} sent {mb:.2}MB of messages");
                    println!("MPC simulation finished successfully!");

                    let result = prg.parse_output(&outputs.pop().unwrap()).unwrap();
                    println!("{calculation} = {result}");
                    assert_eq!(format!("{result}"), format!("{expected}"));
                }
            }
        }
        Ok(())
    }
}
