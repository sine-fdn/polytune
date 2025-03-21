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

## How to Deploy the Engine

The following example shows how to deploy the MPC engine for two parties, based on the SQL integration example (but without showing how and where to deploy the databases). If you want to deploy the engine with more parties or a different Garble program, the same principles apply.

Two Dockerfiles are provided as examples of how to run the MPC engine inside a docker container, `party0.Dockerfile` and `party1.Dockerfile`. They are identical except for the ports that they use, you could of course just use a single Dockerfile in case all of your parties listen on the same port. These Dockerfiles do not contain any DB configuration, it is up to you to either bundle a database into the docker container (similar to how databases are set up using Docker Compose for the tests, see `docker-compose.yml`) or to change the database URLs in the configuration files (`policy0.json` and `policy1.json`) so that DBs that are hosted somewhere else can be accessed.

Assuming that the databases are hosted somewhere else, most of `party0.Dockerfile` (or `party1.Dockerfile`) can stay as it is. Let's take a look at the last three lines to see what you might want to change:

```
EXPOSE 8000
WORKDIR /usr/src/polytune/examples/sql-integration
CMD ["polytune-sql-integration", "--addr=0.0.0.0", "--port=8000", "--config=./policy0.json"]
```

The above Dockerfile exposes the MPC engine on port 8000 and reads its configuration from `policy0.json` (contained here in this repository).

To build and run the container, use the following commands and **make sure to run them from the top level directory of the repository**:

```
docker build -f examples/sql-integration/party0.Dockerfile --tag 'polytune0' .
docker run -t -p 8000:8000 polytune0
```

You will notice that running this docker container will fail, because party 0 is configured to be the leader (in `policy0.json`) and is thus expected all other parties to be listening already:

```
2024-11-18T21:59:17.244221Z  INFO polytune_sql_integration: listening on 0.0.0.0:8000
2024-11-18T21:59:17.244366Z  INFO polytune_sql_integration: Acting as leader (party 0)
2024-11-18T21:59:17.270663Z  INFO polytune_sql_integration: Waiting for confirmation from party http://localhost:8001/
2024-11-18T21:59:17.274310Z ERROR polytune_sql_integration: Could not reach http://localhost:8001/run: error sending request for url (http://localhost:8001/run): error trying to connect: tcp connect error: Cannot assign requested address (os error 99)
Error: Some participants are missing, aborting...
```

To solve this, make sure to deploy and run the contributors first (in this example only party 1, but you could deploy more than two parties, in which case all contributing parties need to be started before the leader starts running), for example:

```
docker build -f examples/sql-integration/party1.Dockerfile --tag 'polytune1' . && docker run -t -p 8001:8001 polytune1
[+] Building 279.4s (20/20) FINISHED
2024-11-18T22:52:32.213120Z  INFO polytune_sql_integration: listening on 0.0.0.0:8001
2024-11-18T22:52:32.213365Z  INFO polytune_sql_integration: Listening for connection attempts from other parties
2024-11-18T22:52:42.214689Z  INFO polytune_sql_integration: Listening for connection attempts from other parties
2024-11-18T22:52:52.216829Z  INFO polytune_sql_integration: Listening for connection attempts from other parties
```

You can check that the party is running and listening by making a GET request to its `/ping` route (in this example thus `localhost:8001/ping`), which should respond with a `pong` message.

Make sure to change the `"participants"` key in the configuration files (in our example case `policy0.json` and `policy1.json`) to the addresses used by the parties. The first address in the array is always the first party, the second address in the array the second party and so on. As a result, the configuration files of the different parties must all use the same `"participants"` array if they want to be able to communicate with each other.

Let's assume that party 0 is listening at `http://1.2.3.4:8000` and party 1 at `http://5.6.7.8:9000`. The configuration files `policy0.json` and `policy1.json` would then both need to contain:

```json
{
  "participants": ["http://1.2.3.4:8000", "http://5.6.7.8:9000"],
  ...
}
```
