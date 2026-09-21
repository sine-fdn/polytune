// End-to-end test for the wasm-http-channels example: runs all three parties
// of the benchmark circuit concurrently against a local broker and checks
// that the computed result is correct.
const assert = require("node:assert");
const { compute } = require("../pkg-node/polytune_wasm_http_channels.js");

const BROKER_URL = process.env.BROKER_URL ?? "http://127.0.0.1:9999";
const SESSION_URL = `${BROKER_URL}/session/mpc-test/`;

// Inputs are chosen so that each party lands in a different bucket relative
// to the average of all three inputs (+/- 10%), exercising all branches of
// the circuit rather than only the trivial "everyone is within range" case.
const INPUTS = [100, 105, 130];
const RANGE_IN_PERCENT = 10;
const EXPECTED = ["Bucket::Below", "Bucket::Within", "Bucket::Above"];

async function main() {
  // Promise.all runs all three parties concurrently, which the protocol
  // requires: each party needs the others actively sending/receiving at
  // the same time, or it just stalls waiting for a party that hasn't started.
  const results = await Promise.all(
    INPUTS.map((input, party) =>
      compute(SESSION_URL, party, input, RANGE_IN_PERCENT)
    )
  );

  for (const [party, result] of results.entries()) {
    assert.deepStrictEqual(
      result,
      EXPECTED,
      `party ${party} returned an unexpected result: ${JSON.stringify(result)}`
    );
  }

  console.log("wasm MPC computation produced the expected result:", results[0]);
}

main().catch((err) => {
  console.error("wasm MPC test failed:", err);
  process.exit(1);
});
