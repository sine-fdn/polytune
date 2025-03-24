# API Integration

This example is more advanced and shows how to provide data using a simple API directly as Garble literals, join them together (using the built-in `join` function of the Garble language) and send the output to an API endpoint that accepts Garble literals.

The example uses two parties, which communicate over MPC without the need for a trusted (or semi-trusted) third party. Each party runs an HTTP server to receive incoming messages and sends messages by sending HTTP requests to the other party. The MPC program as well as any configuration necessary is specified using a JSON configuration that is provided via an API call.

## How to Run the Example

The easiest way to run the example is as a test that orchestrates the two parties:

```
cargo test --release -- --nocapture
```

## How to Deploy the Engine

The following example shows how to deploy the MPC engine for two parties. If you want to deploy the engine with more parties or a different Garble program, the same principles apply.

A simple Dockerfile is provided as an example of how to run the MPC engine inside a docker container. The only thing you might need to change is the port that the MPC engine is listening on:

```
EXPOSE 8000
WORKDIR /usr/src/polytune/examples/api-integration
CMD ["polytune-api-integration", "--addr=0.0.0.0", "--port=8000"]
```

To build and run the container, use the following commands and **make sure to run them from the top level directory of the repository**:

```
docker build -f examples/api-integration/Dockerfile --tag 'polytune0' .
docker run -t -p 8000:8000 polytune0
```

Starting the container does not immediately start an MPC execution, this needs to be explicitly triggered with a POST request to `localhost:8000/launch` while providing the necessary configuration file (see `policy0.json` and `policy1.json` for example configs) as a JSON body.

The `"input"` part of the JSON needs to use Garble's serialization format, as described in the [Garble Serialization How-To](https://garble-lang.org/serde.html). The result of the MPC execution will use the same serialization format and is sent to the endpoint specified as `"output"` in the JSON.

**Please note that you must call `/launch` for all contributors (who will then start waiting for incoming MPC requests) _before_ you call `/launch` for the MPC leader (who will immediately start sending requests to all the other participants and fail if one of them is unreachable).**

You can check that the party is running and listening by making a GET request to its `/ping` route (in this example thus `localhost:8000/ping`), which should respond with a `pong` message.

Make sure to change the `"participants"` key in the configuration files (in our example case `policy0.json` and `policy1.json`) to the addresses used by the parties. The first address in the array is always the first party, the second address in the array the second party and so on. As a result, the configuration files of the different parties must all use the same `"participants"` array if they want to be able to communicate with each other.

Let's assume that party 0 is listening at `http://1.2.3.4:8000` and party 1 at `http://5.6.7.8:9000`. The configuration files `policy0.json` and `policy1.json` would then both need to contain:

```json
{
  "participants": ["http://1.2.3.4:8000", "http://5.6.7.8:9000"],
  ...
}
```