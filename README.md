# Moesif Kong Plugin

The [Moesif Kong plugin](https://docs.konghq.com/hub/moesif/kong-plugin-moesif/) captures API traffic from [Kong API Gateway](https://getkong.org)
and logs it to [Moesif API Analytics](https://www.moesif.com). This plugin leverages an asynchronous design and doesn’t add any latency to your API calls.

- Kong is an open-source API gateway and middleware layer.
- Moesif is an API analytics and monitoring service.

This plugin supports automatic analysis of REST, GraphQL, and other APIs.

[Source Code on GitHub](https://github.com/Moesif/kong-plugin-moesif)

[Package on Luarocks](http://luarocks.org/modules/moesif/kong-plugin-moesif)

## How to install

The .rock file is a self contained package that can be installed locally or from a remote server.

If the luarocks utility is installed in your system (this is likely the case if you used one of the official installation packages), you can install the 'rock' in your LuaRocks tree (a directory in which LuaRocks installs Lua modules).

### 1. Install the Moesif plugin

```bash
luarocks install --server=http://luarocks.org/manifests/moesif kong-plugin-moesif
```

### 2. Update your loaded plugins list
In your `kong.conf`, append `moesif` to the `plugins` field (or `custom_plugins` if old version of Kong). Make sure the field is not commented out.

```yaml
plugins = bundled,moesif         # Comma-separated list of plugins this node
                                 # should load. By default, only plugins
                                 # bundled in official distributions are
                                 # loaded via the `bundled` keyword.
```


If you don't have a `kong.conf`, create one from the default using the following command: 
`cp /etc/kong/kong.conf.default /etc/kong/kong.conf`

### 3. Restart Kong

### 4. Enable the Moesif plugin

```bash
curl -i -X POST --url http://localhost:8001/plugins/ --data "name=moesif" --data "config.application_id=YOUR_APPLICATION_ID";
```

If you experience errors, try restarting Kong and then enable the plugin.

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
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: Your Moesif Application Id can be found in the [_Moesif Portal_](https://www.moesif.com/).
After signing up for a Moesif account, your Moesif Application Id will be displayed during the onboarding steps. 

You can always find your Moesif Application Id at any time by logging 
into the [_Moesif Portal_](https://www.moesif.com/), click on the top right menu,
and then clicking _Installation_.

### Enabling the plugin on a Service

Configure this plugin on a [Service](https://docs.konghq.com/1.0.x/admin-api/#service-object) by making the following request on your Kong server:

```
curl -X POST http://kong:8001/services/{service}/plugins \
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_
- `service`: the id or name of the Service that this plugin configuration will target.


### Enabling the plugin on a Route

Configure this plugin on a [Route](https://docs.konghq.com/1.0.x/admin-api/#Route-object) with:


```
curl -X POST http://kong:8001/routes/{route_id}/plugins \
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```
- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_
- `route_id`: the id of the Route that this plugin configuration will target.

### Enabling the plugin on a Consumer

You can use the `http://localhost:8001/plugins` endpoint to enable this plugin on specific [Consumers](https://docs.konghq.com/1.0.x/admin-api/#Consumer-object):

```
curl -X POST http://kong:8001/plugins \
    --data "name=moesif" \
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
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

## Parameters

The Moesif Kong Plugin has a variety of options for things like data scrubbing and tweaking performance. 

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
|config.timeout (deprecated)|1000|Timeout in milliseconds when connecting/sending data to Moesif.|
|config.connect_timeout|1000|Timeout in milliseconds when connecting to Moesif.|
|config.send_timeout|2000|Timeout in milliseconds when sending data to Moesif.|
|config.keepalive|5000|Value in milliseconds that defines for how long an idle connection will live before being closed.|
|config.api_version|1.0|API Version you want to tag this request with in Moesif.|
|config.disable_capture_request_body|false|Disable logging of request body.|
|config.disable_capture_response_body|false|Disable logging of response body.|
|config.request_header_masks|{}|An array of request header fields to mask.|
|config.request_body_masks|{}|An array of request body fields to mask.|
|config.response_header_masks|{}|An array of response header fields to mask.|
|config.response_body_masks|{}|An array of response body fields to mask.|
|config.batch_size|200|Maximum batch size when sending to Moesif.|
|config.user_id_header|X-Consumer-Custom-Id|Request or response header to use to identify the User in Moesif.|
|config.company_id_header||Request or response header to use to identify the Company (Account) in Moesif.|
|config.disable_gzip_payload_decompression|false|If set to true, will disable decompressing body in Kong.|
|config.max_callback_time_spent|2000|Maximum callback time to send even to Moesif.|
|config.max_body_size_limit|100000|Mximum request/response body size in bytes to log in Moesif.|
|config.event_queue_size|5000|Maximum number of events to hold in queue before sending to Moesif. In case of network issues when not able to connect/send event to Moesif, skips adding new to event to queue to prevent memory overflow.|
|config.debug|false|If set to true, prints internal log messages for debugging integration issues.|


## Troubleshooting
If you want to access debug logs, or to send to Moesif support, you can enable debug logs via the following:

```
curl -X POST http://kong:8001/apis/{api}/plugins \
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
    --data "config.debug=true"
```

You should also set log_level to debug in /etc/kong/kong.conf. 

## Tested Version

For tested versions, [see this page](https://docs.konghq.com/hub/moesif/kong-plugin-moesif/) on Kong docs. 

## Other integrations

To view more documentation on integration options, please visit __[the Integration Options Documentation](https://www.moesif.com/docs/getting-started/integration-options/).__
