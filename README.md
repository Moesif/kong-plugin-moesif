# Moesif kong plugin

The [Moesif Kong plugin](https://docs.konghq.com/hub/moesif/kong-plugin-moesif/) integrates [Kong API Gateway](https://getkong.org)
with [Moesif API Analytics](https://www.moesif.com).

- Kong is an open source API gateway and management layer.
- Moesif is an API analytics and debugging service.

When enabled, this plugin will capture API requests and responses and log to Moesif API Insights for easy inspecting and real-time debugging of your API traffic.
Support for REST, GraphQL, Ethereum Web3, JSON-RPC, SOAP, & more

[Source Code on GitHub](https://github.com/Moesif/kong-plugin-moesif)

[Package on Luarocks](http://luarocks.org/modules/moesif/kong-plugin-moesif)

## How to install

The .rock file is a self contained package that can be installed locally or from a remote server.

If the luarocks utility is installed in your system (this is likely the case if you used one of the official installation packages), you can install the 'rock' in your LuaRocks tree (a directory in which LuaRocks installs Lua modules).

It can be installed from luarocks repository by doing:

```shell
luarocks install --server=http://luarocks.org/manifests/moesif kong-plugin-moesif
```

## How to use

How to configure Kong Moesif plugin:

### Terminology
- `plugin`: a plugin executing actions inside Kong before or after a request has been proxied to the upstream API.
- `Service`: the Kong entity representing an external upstream API or microservice.
- `Route`: the Kong entity representing a way to map downstream requests to upstream services.
- `Consumer`: the Kong entity representing a developer or machine using the API. When using Kong, a Consumer only communicates with Kong which proxies every call to the said upstream API.
- `Credential`: a unique string associated with a Consumer, also referred to as an API key.
upstream service: this refers to your own API/service sitting behind Kong, to which client requests are forwarded.
- `API`: a legacy entity used to represent your upstream services. Deprecated in favor of Services since CE 0.13.0 and EE 0.32.

### Enabling the plugin Globally

A plugin which is not associated to any Service, Route or Consumer (or API, if you are using an older version of Kong) is considered "global",
and will be run on every request. Read the [Plugin Reference](https://docs.konghq.com/1.0.x/admin-api/#add-plugin) and the
[Plugin Precedence](https://docs.konghq.com/1.0.x/admin-api/#precedence) sections for more information.

```
curl -X POST http://localhost:8001/plugins \
    --data "name=kong-plugin-moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_

### Enabling the plugin on a Service

Configure this plugin on a [Service](https://docs.konghq.com/1.0.x/admin-api/#service-object) by making the following request on your Kong server:

```
curl -X POST http://kong:8001/services/{service}/plugins \
    --data "name=kong-plugin-moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_
- `service`: the id or name of the Service that this plugin configuration will target.


### Enabling the plugin on a Route

Configure this plugin on a [Route](https://docs.konghq.com/1.0.x/admin-api/#Route-object) with:


```
curl -X POST http://kong:8001/routes/{route_id}/plugins \
    --data "name=kong-plugin-moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```
- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_
- `route_id`: the id of the Route that this plugin configuration will target.

### Enabling the plugin on a Consumer

You can use the `http://localhost:8001/plugins` endpoint to enable this plugin on specific [Consumers](https://docs.konghq.com/1.0.x/admin-api/#Consumer-object):

```
curl -X POST http://kong:8001/plugins \
    --data "name=kong-plugin-moesif" \
    --data "consumer_id={consumer_id}"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_
- `consumer_id`: the id of the Consumer we want to associate with this plugin.

You can combine `consumer_id` and `service_id` in the same request, to furthermore narrow the scope of the plugin.

### Enabling the plugin on an API

If you are using an older version of Kong with the legacy [API entity](https://docs.konghq.com/0.13.x/admin-api/#api-object)
(deprecated in favor of Services since CE 0.13.0 and EE 0.32.),
you can configure this plugin on top of such an API by making the following request:

```
curl -X POST http://kong:8001/apis/{api}/plugins \
    --data "name=kong-plugin-moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_
- `api`: either id or name of the API that this plugin configuration will target.

## Parameters

Here's a list of all the parameters which can be used in this plugin's configuration:

|Parameter|Default|Description|
|---|---|---|
|name||The name of the plugin to use, in this case kong-plugin-moesif|
|service_id||The id of the Service which this plugin will target.|
|route_id	||The id of the Route which this plugin will target.|
|enabled|true|Whether this plugin will be applied.|
|consumer_id||The id of the Consumer which this plugin will target.|
|api_id||The id of the API which this plugin will target. Note: The API Entity is deprecated in favor of Services since CE 0.13.0 and EE 0.32.|
|config.application_id	||The Moesif application token provided to you by Moesif.|
|config.api_endpoint|https://api.moesif.net|URL for the Moesif API.|
|config.timeout|10000|An optional timeout in milliseconds when sending data to Moesif.|
|config.keepalive|10000|An optional value in milliseconds that defines for how long an idle connection will live before being closed.|
|config.api_version|1.0|An optional API Version you want to tag this request with in Moesif.|
|config.disable_capture_request_body|false|An option to disable logging of request body.|
|config.disable_capture_response_body|false|An option to disable logging of response body.|
|config.request_masks|{}|An option to mask a specific request body field.|
|config.response_masks|{}|An option to mask a specific response body field.|

## Other integrations

To view more more documentation on integration options, please visit __[the Integration Options Documentation](https://www.moesif.com/docs/getting-started/integration-options/).__
