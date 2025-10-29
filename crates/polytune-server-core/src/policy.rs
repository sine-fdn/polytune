use std::fmt::Debug;
use std::{collections::HashMap, fmt::Write};

use garble_lang::literal::Literal as GarbleLiteral;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

/// A policy containing everything necessary to run an MPC session.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct Policy {
    /// The unique `computation_id` of this mpc execution. This is used to identify
    /// which `/launch/` requests belong to the same computation.
    pub computation_id: Uuid,
    /// The URLs at which we can reach the other parties. Their position in
    /// in this array needs to be identical for all parties and will correspond
    /// to their party ID (e.g. used for the leader).
    pub participants: Vec<Url>,
    /// The program as [Garble](https://garble-lang.org/) source code.
    pub program: String,
    /// The id of the leader of the computation.
    pub leader: usize,
    /// Our own party ID. Corresponds to our adress at participants\[party\].
    pub party: usize,
    /// The input to the Garble program as a serialized Garble `Literal` value.
    pub input: GarbleLiteral,
    /// The optional output URL to which the output of the MPC computation is provided
    /// as a json serialized Garble `Literal` value.
    pub output: Option<Url>,
    /// The constants needed of this party for the MPC computation. Note that the
    /// identifier must not contain the `PARTY_{ID}::` prefix, but only the name.
    /// E.g. if the Garble program contains `const ROWS_0: usize = PARTY_0::ROWS;`
    /// this should contain e.g. `"ROWS": { "NumUnsigned": [200, "Usize"]}`.
    pub constants: HashMap<String, GarbleLiteral>,
}

impl Policy {
    /// Calculate the hash of a policy's program.
    /// This hash is used during Policy validation with the other parties.
    pub fn program_hash(&self) -> String {
        blake3::hash(self.program.as_bytes()).to_string()
    }

    /// Iterator of other party Ids, excluding self.party.
    pub fn other_parties(&self) -> impl Iterator<Item = usize> + Clone {
        (0..self.participants.len()).filter(|p| *p != self.party)
    }

    /// All party Ids.
    pub fn party_ids(&self) -> Vec<usize> {
        (0..self.participants.len()).collect()
    }
}

impl Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("computation_id", &self.computation_id)
            .field("participants", &debug_urls_as_display(&self.participants)?)
            .field("program", &self.program)
            .field("leader", &self.leader)
            .field("party", &self.party)
            // We don't want to potentially log the sensitive input information
            .field("input", &"<REDACTED>")
            .field("output", &self.output)
            .field("constants", &self.constants)
            .finish()
    }
}

fn debug_urls_as_display(urls: &[Url]) -> Result<String, std::fmt::Error> {
    let mut s = "[".to_string();
    let mut iter = urls.iter();
    if let Some(url) = iter.next() {
        write!(&mut s, "{url}")?;
    }
    for url in iter {
        write!(&mut s, ", {url}")?;
    }
    s.push(']');
    Ok(s)
}
