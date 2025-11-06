# Polytune HTTP Server

This crate implements a full-fledged MPC server which can receive requests containing a program specified as a Garble program, coordinate with multiple instances of this server, execute the provided program securely using Polytune, and return the result.

The MPC program as well as any configuration necessary is specified using a JSON configuration that is provided via an API call to the `polytune-server`.

## How to Deploy the Engine

The following example shows how to deploy the MPC engine for two parties. If you want to deploy the engine with more parties or a different Garble program, the same principles apply.

A simple [Dockerfile](./Dockerfile) is provided as an example of how to run the MPC engine inside a docker container.

To build and run the container, use the following commands and **make sure to run them from the top level directory of the repository**:

```
docker build -f crates/polytune-http-server/Dockerfile --tag 'polytune-http-server' .
docker run -t -p 8000:8000 polytune-http-server
```

Starting the container does not immediately start an MPC execution, this needs to be explicitly triggered with a POST request to `localhost:8000/schedule` while providing the necessary configuration file (see `policy0.json` and `policy1.json` for example configs) as a JSON body.

The `"input"` part of the JSON needs to use Garble's serialization format, as described in the [Garble Serialization How-To](https://garble-lang.org/serde.html). The result of the MPC execution will use the same serialization format and is sent to the endpoint specified as `"output"` in the JSON.

**Please note that a call to `/schedule` only returns once it has been called for all parties with the same computation ID.**

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

## Logging
The logging output of the server can be configured using the `POLYTUNE_LOG` environment variable using an [`EnvFilter` directive](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html).
