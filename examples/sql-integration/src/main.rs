use anyhow::{anyhow, bail, Context, Error};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{Request, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use polytune::{
    channel::{Channel, RecvInfo, SendInfo},
    garble_lang::{
        ast::{Type, Variant},
        compile_with_constants,
        literal::{Literal, VariantLiteral},
        token::{SignedNumType, UnsignedNumType},
    },
    protocol::mpc,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{
    any::{install_default_drivers, AnyQueryResult, AnyRow},
    AnyPool, Pool, Row, ValueRef,
};
use std::{
    borrow::BorrowMut,
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::exit,
    result::Result,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    fs,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    time::{sleep, timeout},
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn, Span};
use url::Url;

/// A CLI for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "polytune")]
struct Cli {
    /// The IP address to listen on for connection attempts from other parties.
    #[arg(long, short)]
    addr: Option<String>,
    /// The port to listen on for connection attempts from other parties.
    #[arg(long, short)]
    port: Option<u16>,
    /// The location of the file with the policy configuration.
    #[arg(long, short)]
    config: PathBuf,
}

/// A policy containing everything necessary to run an MPC session, read from a JSON config file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Policy {
    participants: Vec<Url>,
    program: PathBuf,
    leader: usize,
    party: usize,
    input: Option<DbQuery>,
    output: Option<DbQuery>,
    constants: HashMap<String, String>,
}

/// All the details required to connect to a database, with an optional setup step to run before.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DbQuery {
    db: String,
    setup: Option<String>,
    query: String,
}

/// HTTP request coming from another party to start an MPC session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct PolicyRequest {
    participants: Vec<Url>,
    program_hash: String,
    leader: usize,
}

/// HTTP request to transmit constants necessary to compile a program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ConstsRequest {
    consts: HashMap<String, Literal>,
}

struct MpcComms {
    consts: HashMap<String, HashMap<String, Literal>>,
    senders: Vec<Sender<Vec<u8>>>,
}

type MpcState = Arc<Mutex<MpcComms>>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    install_default_drivers();
    let Cli { addr, port, config } = Cli::parse();
    let Ok(policy) = fs::read_to_string(&config).await else {
        error!("Could not find '{}', exiting...", config.display());
        exit(-1);
    };
    let policy = match serde_json::from_str::<Policy>(&policy) {
        Ok(policy) => policy,
        Err(e) => {
            bail!("'{}' has an invalid format: {e}", config.display());
        }
    };

    let state = Arc::new(Mutex::new(MpcComms {
        consts: HashMap::new(),
        senders: vec![],
    }));

    let log_layer = TraceLayer::new_for_http()
        .on_request(|r: &Request<_>, _: &Span| tracing::info!("{} {}", r.method(), r.uri().path()))
        .on_response(
            |r: &Response<_>, latency: Duration, _: &Span| match r.status().as_u16() {
                400..=499 => tracing::warn!("{} (in {:?})", r.status(), latency),
                500..=599 => tracing::error!("{} (in {:?})", r.status(), latency),
                _ => tracing::info!("{} (in {:?})", r.status(), latency),
            },
        );

    let app = Router::new()
        // to check whether a server is running:
        .route("/ping", get(ping))
        // to kick off an MPC session:
        .route("/run", post(run))
        // to receive constants from other parties:
        .route("/consts/:from", post(consts))
        // to receive MPC messages during the execution of the core protocol:
        .route("/msg/:from", post(msg))
        .with_state((policy.clone(), Arc::clone(&state)))
        .layer(DefaultBodyLimit::disable())
        .layer(ServiceBuilder::new().layer(log_layer));

    let addr = if let Ok(socket_addr) = env::var("SOCKET_ADDRESS") {
        SocketAddr::from_str(&socket_addr)
            .unwrap_or_else(|_| panic!("Invalid socket address: {socket_addr}"))
    } else {
        let addr = addr.unwrap_or_else(|| "127.0.0.1".into());
        let port = port.unwrap_or(8000);
        match addr.parse::<IpAddr>() {
            Ok(addr) => SocketAddr::new(addr, port),
            Err(_) => {
                error!("Invalid IP address: {addr}, using 127.0.0.1 instead");
                SocketAddr::from(([127, 0, 0, 1], port))
            }
        }
    };
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // If we are not the policy leader we need to wait for HTTP messages and do nothing else.
    if policy.leader != policy.party {
        loop {
            info!("Listening for connection attempts from other parties");
            sleep(Duration::from_secs(10)).await;
        }
    }
    info!("Acting as leader (party {})", policy.leader);
    let Ok(code) = fs::read_to_string(&policy.program).await else {
        bail!("Could not load program {:?}", &policy.program);
    };
    let hash = blake3::hash(code.as_bytes()).to_string();
    let client = reqwest::Client::new();
    let policy_request = PolicyRequest {
        participants: policy.participants.clone(),
        leader: policy.leader,
        program_hash: hash,
    };
    // As a leader, we first make sure that all other participants join the session:
    let mut participant_missing = false;
    for party in policy.participants.iter() {
        if party != &policy.participants[policy.party] {
            info!("Waiting for confirmation from party {party}");
            let url = format!("{party}run");
            match client.post(&url).json(&policy_request).send().await {
                Err(err) => {
                    error!("Could not reach {url}: {err}");
                    participant_missing = true;
                    continue;
                }
                Ok(res) => match res.status() {
                    StatusCode::OK => {}
                    code => {
                        error!(
                            "Unexpected response while trying to start execution for {url}: {code}"
                        );
                        participant_missing = true;
                    }
                },
            }
        }
    }
    if participant_missing {
        bail!("Some participants are missing, aborting...");
    }
    // Now we start the MPC session, then decode the output and write it to the output DB:
    info!("All participants have accepted the session, starting calculation now...");
    match execute_mpc(Arc::clone(&state), code, &policy).await {
        Ok(Some(output)) => match decode_literal(output) {
            Ok(rows) => {
                let n_rows = rows.len();
                if let Some(output) = &policy.output {
                    let DbQuery { db, setup, query } = output;
                    info!("Connecting to output db at {db}...");
                    let pool: AnyPool = Pool::connect(db).await?;
                    if let Some(setup) = setup {
                        let result: AnyQueryResult = sqlx::query(setup).execute(&pool).await?;
                        let rows_affected = result.rows_affected();
                        debug!("{rows_affected} rows affected by '{setup}'");
                    }
                    for row in rows {
                        let mut query = sqlx::query(query);
                        for field in row {
                            query = query.bind(field);
                        }
                        let result: AnyQueryResult = query.execute(&pool).await?;
                        let rows = result.rows_affected();
                        debug!("Inserted {rows} row(s)");
                    }
                } else {
                    warn!("No 'output' and/or 'output_db' specified in the policy, dropping {n_rows} rows");
                }
                info!("MPC Output: {n_rows} rows")
            }
            Err(e) => error!("MPC Error: {e}"),
        },
        Ok(None) => {}
        Err(e) => {
            error!("Error while executing MPC: {e}")
        }
    }
    Ok(())
}

async fn execute_mpc(
    state: MpcState,
    code: String,
    policy: &Policy,
) -> Result<Option<Literal>, Error> {
    let Policy {
        program: _program,
        leader,
        participants,
        party,
        input,
        output: _output,
        constants,
    } = policy;
    let now = Instant::now();
    let Some(DbQuery { db, query, .. }) = input else {
        bail!("Policy must specify an input DB");
    };
    info!("Connecting to input db at {db}...");
    let pool: AnyPool = Pool::connect(db).await?;
    let rows: Vec<AnyRow> = sqlx::query(query).fetch_all(&pool).await?;
    info!("'{query}' returned {} rows from {db}", rows.len());

    // Compiling the circuit might require constants, so we compute them:
    let mut my_consts = HashMap::new();
    for (k, query) in constants {
        let row: AnyRow = sqlx::query(query).fetch_one(&pool).await?;
        if row.len() != 1 {
            bail!(
                "Expected a single value, but got {} from '{query}'",
                row.len(),
            );
        } else {
            let n = if let Ok(n) = row.try_get::<i32, _>(0) {
                n as i64
            } else if let Ok(n) = row.try_get::<i64, _>(0) {
                n
            } else {
                bail!("Could not decode scalar value as usize using '{query}'");
            };
            if n < 0 {
                bail!("Value is < 0 for '{query}'");
            }
            my_consts.insert(
                k.clone(),
                Literal::NumUnsigned(n as u64, UnsignedNumType::Usize),
            );
            continue;
        }
    }
    {
        let mut locked = state.lock().await;
        locked
            .consts
            .insert(format!("PARTY_{party}"), my_consts.clone());
    }
    // Now we sent around the constants to the other parties...
    let client = reqwest::Client::new();
    for p in participants.iter() {
        if p != &participants[*party] {
            info!("Sending constants to party {p}");
            let url = format!("{p}consts/{party}");
            let const_request = ConstsRequest {
                consts: my_consts.clone(),
            };
            let Ok(res) = client.post(&url).json(&const_request).send().await else {
                bail!("Could not reach {url}");
            };
            match res.status() {
                StatusCode::OK => {}
                code => {
                    bail!("Unexpected response while trying to send consts to {url}: {code}");
                }
            }
        }
    }
    // ...and wait for their constants:
    loop {
        sleep(Duration::from_millis(500)).await;
        let locked = state.lock().await;
        if locked.consts.len() >= participants.len() - 1 {
            break;
        } else {
            let missing = participants.len() - 1 - locked.consts.len();
            info!(
                "Constants missing from {} parties, received constants from {:?}",
                missing,
                locked.consts.keys()
            );
        }
    }

    // After receiving the constants, we can finally compile the circuit:
    let prg = {
        let locked = state.lock().await;
        info!("Compiling circuit with the following constants:");
        for (p, v) in locked.consts.iter() {
            for (k, v) in v {
                info!("{p}::{k}: {v:?}");
            }
        }
        compile_with_constants(&code, locked.consts.clone())
            .map_err(|e| anyhow!(e.prettify(&code)))?
    };

    // Now we need to load our input rows from the DB and convert it to a Garble array:
    let input_ty = &prg.main.params[*party].ty;
    let Type::ArrayConst(row_type, _) = input_ty else {
        bail!("Expected an array input type (with const size) for party {party}, but found {input_ty}");
    };
    let Type::Tuple(field_types) = row_type.as_ref() else {
        bail!("Expected an array of tuples as input type for party {party}, but found {input_ty}");
    };
    info!(
        "Trying to execute circuit with {:.2}M gates ({:.2}M AND gates)",
        prg.circuit.gates.len() as f64 / 1000.0 / 1000.0,
        prg.circuit.and_gates() as f64 / 1000.0 / 1000.0
    );
    let mut rows_as_literals = vec![];
    for (r, row) in rows.iter().enumerate() {
        let mut row_as_literal = vec![];
        if field_types.len() != row.len() {
            bail!(
                    "The program expects a tuple with {} fields, but the query returned a row with {} fields",
                    field_types.len(),
                    row.len()
                );
        }
        for (c, field_type) in field_types.iter().enumerate() {
            let mut literal = None;
            match field_type {
                Type::Bool => {
                    if let Ok(b) = row.try_get::<bool, _>(c) {
                        literal = Some(Literal::from(b))
                    }
                }
                Type::Unsigned(UnsignedNumType::U8) => {
                    if let Ok(n) = row.try_get::<i32, _>(c) {
                        if n >= 0 && n <= u8::MAX as i32 {
                            literal = Some(Literal::NumUnsigned(n as u64, UnsignedNumType::U8))
                        }
                    }
                }
                Type::Unsigned(UnsignedNumType::U16) => {
                    if let Ok(n) = row.try_get::<i32, _>(c) {
                        if n >= 0 && n <= u16::MAX as i32 {
                            literal = Some(Literal::NumUnsigned(n as u64, UnsignedNumType::U16))
                        }
                    }
                }
                Type::Unsigned(UnsignedNumType::U32) => {
                    if let Ok(n) = row.try_get::<i32, _>(c) {
                        if n >= 0 && n <= u32::MAX as i32 {
                            literal = Some(Literal::NumUnsigned(n as u64, UnsignedNumType::U32))
                        }
                    }
                }
                Type::Unsigned(UnsignedNumType::U64) => {
                    if let Ok(n) = row.try_get::<i32, _>(c) {
                        if n >= 0 {
                            literal = Some(Literal::NumUnsigned(n as u64, UnsignedNumType::U64))
                        }
                    }
                }
                Type::Signed(SignedNumType::I8) => {
                    if let Ok(n) = row.try_get::<i32, _>(c) {
                        if n >= i8::MIN as i32 && n <= i8::MAX as i32 {
                            literal = Some(Literal::NumSigned(n as i64, SignedNumType::I8))
                        }
                    }
                }
                Type::Signed(SignedNumType::I16) => {
                    if let Ok(n) = row.try_get::<i32, _>(c) {
                        if n >= i16::MIN as i32 && n <= i16::MAX as i32 {
                            literal = Some(Literal::NumSigned(n as i64, SignedNumType::I16))
                        }
                    }
                }
                Type::Signed(SignedNumType::I32) => {
                    if let Ok(n) = row.try_get::<i32, _>(c) {
                        literal = Some(Literal::NumSigned(n as i64, SignedNumType::I32))
                    }
                }
                Type::Signed(SignedNumType::I64) => {
                    if let Ok(n) = row.try_get::<i64, _>(c) {
                        literal = Some(Literal::NumSigned(n, SignedNumType::I64))
                    }
                }
                Type::Array(ty, size) if ty.as_ref() == &Type::Unsigned(UnsignedNumType::U8) => {
                    if let Ok(s) = row.try_get::<String, _>(c) {
                        let mut fixed_str =
                            vec![Literal::NumUnsigned(0, UnsignedNumType::U8); *size];
                        for (i, b) in s.as_bytes().iter().enumerate() {
                            if i < *size {
                                fixed_str[i] = Literal::NumUnsigned(*b as u64, UnsignedNumType::U8);
                            } else {
                                warn!(
                                    "String is longer than {size} bytes: '{s}', dropping '{}'",
                                    &s[i..]
                                );
                                break;
                            }
                        }
                        literal = Some(Literal::Array(fixed_str))
                    }
                }
                Type::ArrayConst(ty, size)
                    if ty.as_ref() == &Type::Unsigned(UnsignedNumType::U8) =>
                {
                    let size = *prg.const_sizes.get(size).unwrap();
                    let mut str = None;
                    if let Ok(s) = row.try_get::<String, _>(c) {
                        str = Some(s)
                    } else if let Ok(s) = row.try_get::<Vec<u8>, _>(c) {
                        if let Ok(s) = String::from_utf8(s) {
                            str = Some(s)
                        }
                    }
                    if let Some(s) = str {
                        let mut fixed_str =
                            vec![Literal::NumUnsigned(0, UnsignedNumType::U8); size];
                        for (i, b) in s.as_bytes().iter().enumerate() {
                            if i < size {
                                fixed_str[i] = Literal::NumUnsigned(*b as u64, UnsignedNumType::U8);
                            } else {
                                warn!(
                                    "String is longer than {size} bytes: '{s}', dropping '{}'",
                                    &s[i..]
                                );
                                break;
                            }
                        }
                        literal = Some(Literal::Array(fixed_str))
                    }
                }
                Type::Enum(name) => {
                    let Some(enum_def) = prg.program.enum_defs.get(name) else {
                        bail!("Could not find definition for enum {name} in program");
                    };
                    let mut str = None;
                    if let Ok(s) = row.try_get::<String, _>(c) {
                        str = Some(s)
                    } else if let Ok(s) = row.try_get::<Vec<u8>, _>(c) {
                        if let Ok(s) = String::from_utf8(s) {
                            str = Some(s)
                        }
                    }
                    if let Some(variant) = str {
                        for v in &enum_def.variants {
                            if let Variant::Unit(variant_name) = v {
                                if variant_name.to_lowercase() == variant.to_lowercase() {
                                    literal = Some(Literal::Enum(
                                        name.clone(),
                                        variant_name.clone(),
                                        VariantLiteral::Unit,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            if let Some(literal) = literal {
                row_as_literal.push(literal);
            } else if let Ok(raw) = row.try_get_raw(c) {
                bail!(
                    "Could not decode column {c} with type {}, column has type {}",
                    field_types[c],
                    raw.type_info()
                );
            } else {
                bail!("Could not decode column {c} with type {}", field_types[c]);
            }
        }
        let literal = Literal::Tuple(row_as_literal);
        debug!("rows[{r}] = {literal}");
        rows_as_literals.push(literal);
    }
    let literal = Literal::Array(rows_as_literals);
    let input = prg.literal_arg(*party, literal)?.as_bits();

    // Now that we have our input, we can start the actual session without a trusted third party:
    let p_out: Vec<_> = vec![*leader];
    let mut channel = {
        let mut locked = state.lock().await;
        let state = locked.borrow_mut();
        if !state.senders.is_empty() {
            panic!("Cannot start a new MPC execution while there are still active senders!");
        }
        let mut receivers = vec![];
        for _ in 0..policy.participants.len() {
            let (s, r) = channel(1);
            state.senders.push(s);
            receivers.push(Mutex::new(r));
        }

        HttpChannel {
            urls: participants.clone(),
            party: *party,
            recv: receivers,
        }
    };

    // We run the computation using MPC, which might take some time...
    let output = mpc(&mut channel, &prg.circuit, &input, 0, *party, &p_out).await?;

    // ...and now we are done and return the output (if there is any):
    state.lock().await.senders.clear();
    let elapsed = now.elapsed();
    info!(
        "MPC computation for party {party} took {} hour(s), {} minute(s), {} second(s)",
        elapsed.as_secs() / 60 / 60,
        (elapsed.as_secs() % (60 * 60)) / 60,
        elapsed.as_secs() % 60,
    );
    if output.is_empty() {
        Ok(None)
    } else {
        Ok(Some(prg.parse_output(&output)?))
    }
}

fn decode_literal(l: Literal) -> Result<Vec<Vec<String>>, String> {
    let Literal::Array(rows) = l else {
        return Err(format!("Expected an array of rows, but found {l}"));
    };
    let mut records = vec![];
    for row in rows {
        let row = match row {
            Literal::Tuple(row) => row,
            record => vec![record],
        };
        let mut record = vec![];
        fn stringify(elements: &[Literal]) -> Option<String> {
            let mut bytes = vec![];
            for e in elements {
                if let Literal::NumUnsigned(n, UnsignedNumType::U8) = e {
                    if *n != 0 {
                        bytes.push(*n as u8);
                    }
                } else {
                    return None;
                }
            }
            String::from_utf8(bytes).ok()
        }
        for col in row {
            record.push(match col {
                Literal::True => "true".to_string(),
                Literal::False => "false".to_string(),
                Literal::NumUnsigned(n, _) => n.to_string(),
                Literal::NumSigned(n, _) => n.to_string(),
                Literal::Array(elements) => match stringify(&elements) {
                    Some(s) => format!("'{s}'"),
                    None => format!("'{}'", Literal::Array(elements)),
                },
                l => format!("'{l}'"),
            });
        }
        records.push(record);
    }
    Ok(records)
}

async fn ping() -> &'static str {
    "pong"
}

async fn run(State((policy, state)): State<(Policy, MpcState)>, Json(body): Json<PolicyRequest>) {
    if policy.participants != body.participants || policy.leader != body.leader {
        error!("Policy not accepted: {body:?}");
        return;
    }
    let Ok(code) = fs::read_to_string(&policy.program).await else {
        error!("Could not load program {:?}", &policy.program);
        return;
    };
    let expected = blake3::hash(code.as_bytes()).to_string();
    if expected != body.program_hash {
        error!("Aborting due to different hashes for program in policy {policy:?}");
        return;
    }
    info!(
        "Accepted policy for {}, starting execution",
        policy.program.display()
    );
    tokio::spawn(async move {
        if let Err(e) = execute_mpc(state, code, &policy).await {
            error!("{e}");
        }
    });
}

async fn consts(
    State((_, state)): State<(Policy, MpcState)>,
    Path(from): Path<u32>,
    Json(body): Json<ConstsRequest>,
) {
    let mut state = state.lock().await;
    state.consts.insert(format!("PARTY_{from}"), body.consts);
}

async fn msg(State((_, state)): State<(Policy, MpcState)>, Path(from): Path<u32>, body: Bytes) {
    let state = state.lock().await;
    if state.senders.len() > from as usize {
        state.senders[from as usize]
            .send(body.to_vec())
            .await
            .unwrap();
    } else {
        error!("No sender for party {from}");
    }
}

struct HttpChannel {
    urls: Vec<Url>,
    party: usize,
    recv: Vec<Mutex<Receiver<Vec<u8>>>>,
}

impl Channel for HttpChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        info: SendInfo,
    ) -> Result<(), Self::SendError> {
        let simulated_delay_in_ms = 300;
        let client = reqwest::Client::new();
        let url = format!("{}msg/{}", self.urls[p], self.party);
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        let i = info.sent();
        let total = info.total();
        let phase = info.phase();
        if i == 1 {
            info!("Sending msg {phase} to party {p} ({mb:.2}MB), {i}/{total}...");
        } else {
            info!("  (sending msg {phase} to party {p} ({mb:.2}MB), {i}/{total})");
        }
        loop {
            sleep(Duration::from_millis(simulated_delay_in_ms)).await;
            let req = client.post(&url).body(msg.clone()).send();
            let Ok(Ok(res)) = timeout(Duration::from_secs(1), req).await else {
                warn!("  req timeout: chunk {}/{} for party {}", i + 1, total, p);
                continue;
            };
            match res.status() {
                StatusCode::OK => break Ok(()),
                StatusCode::NOT_FOUND => {
                    error!("Could not reach party {p} at {url}...");
                    sleep(Duration::from_millis(1000)).await;
                }
                status => {
                    error!("Unexpected status code: {status}");
                    anyhow::bail!("Unexpected status code: {status}")
                }
            }
        }
    }

    async fn recv_bytes_from(&self, p: usize, _info: RecvInfo) -> Result<Vec<u8>, Self::RecvError> {
        let mut r = self.recv[p].lock().await;
        timeout(Duration::from_secs(30 * 60), r.recv())
            .await
            .context(format!("recv_bytes_from(p = {p})"))?
            .ok_or_else(|| anyhow!("Expected a message, but received `None`!"))
    }
}
