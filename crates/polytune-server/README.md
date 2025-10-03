# Polytune Server

`/launch`

Schedules an MPC computation for execution. `/launch` needs to be called with the same
UUID, participants, program, and leader for all parties listed in `participants`. Once `/launch` 
is called on all of them, the parties will start executing the provided program with the inputs.
`/launch` returns with 200 if the computation is succesfully started, or with an error if there
was an issue in coordinating the computation, exchanging the constants, or compiling the circuit.

TODO: Should `/launch` return before compiling the circ, or after? This can take multiple minutes
and timeouts for `/launch` call need to be set appropriately. Alternatively, errors in compilation, etc.
could also be sent to the output endpoint.




-----

This crate implements a full-fledged MPC server which can receive requests containing a program specified as a Garble program, coordinate with multiple instances of this server, execute the provided program securely using Polytune, and return the result.

The MPC program as well as any configuration necessary is specified using a JSON configuration that is provided via an API call to the `polytune-server`.

## How to Deploy the Engine

The following example shows how to deploy the MPC engine for two parties. If you want to deploy the engine with more parties or a different Garble program, the same principles apply.

A simple Dockerfile is provided as an example of how to run the MPC engine inside a docker container. The only thing you might need to change is the port that the MPC engine is listening on:

```
EXPOSE 8000
WORKDIR /usr/src/polytune/crates/polytune-server
CMD ["polytune-server", "--addr=0.0.0.0", "--port=8000"]
```

To build and run the container, use the following commands and **make sure to run them from the top level directory of the repository**:

```
docker build -f crates/polytune-server/Dockerfile --tag 'polytune-server' .
docker run -t -p 8000:8000 polytune-server
```

Starting the container does not immediately start an MPC execution, this needs to be explicitly triggered with a POST request to `localhost:8000/launch` while providing the necessary configuration file (see `policy0.json` and `policy1.json` for example configs) as a JSON body.

The `"input"` part of the JSON needs to use Garble's serialization format, as described in the [Garble Serialization How-To](https://garble-lang.org/serde.html) (or as JsonSchema as part of the OpenAPI spec at `/api.json`). The result of the MPC execution will use the same serialization format and is sent to the endpoint specified as `"output"` in the JSON.

You can check that the party is running and listening by making a GET request to its `/ping` route (in this example thus `localhost:8000/ping`), which should respond with a `pong` message.

Make sure to change the `"participants"` key in the configuration files (in our example case `policy0.json` and `policy1.json`) to the addresses used by the parties. The first address in the array is always the first party, the second address in the array the second party and so on. As a result, the configuration files of the different parties must all use the same `"participants"` array if they want to be able to communicate with each other.

Let's assume that party 0 is listening at `http://1.2.3.4:8000` and party 1 at `http://5.6.7.8:9000`. The configuration files `policy0.json` and `policy1.json` would then both need to contain:

```json
{
  "participants": ["http://1.2.3.4:8000", "http://5.6.7.8:9000"],
  ...
}
```

## OpenAPI spec
The server provides an OpenAPI spec at `/api.json` and a Swagger UI for the spec at `/swagger`.