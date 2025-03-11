use polytune::garble_lang::compile;

use polytune_sync_channel::{simulate_mpc_sync, Error};

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
                let output = simulate_mpc_sync(&prg.circuit, &[&x, &y, &z], &output_parties, false)?;
                let result = prg.parse_output(&output).unwrap();
                println!("{calculation} = {result}");
                assert_eq!(format!("{result}"), format!("{expected}"));
            }
        }
    }
    Ok(())
}