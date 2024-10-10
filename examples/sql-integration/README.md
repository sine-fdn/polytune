# SQL Integration

This example is more advanced and shows how to load data from different input databases (PostgreSQL + MySQL), convert the rows to Garble language data types, join them together (using the built-in `join` function of the Garble language) and write the output to a third (PostgreSQL) database.

The example uses two parties, which communicate over MPC without the need for a trusted (or semi-trusted) third party. Each party runs an HTTP server to receive incoming messages and sends messages by sending HTTP requests to the other party. The MPC program as well as any configuration necessary to read from / write to databases is specified in a JSON policy file which is read on startup.

## How to Run the Example

Make sure that Docker is running (used to spin up the databases), then seed the databases:

```
docker compose -f docker-compose.yml up -d
```

The easiest way to run the example is as a test that orchestrates the two parties:

```
cargo test --release -- --nocapture
```
