# Moesif Kong Plugin

The [Moesif Kong plugin](https://docs.konghq.com/hub/moesif/kong-plugin-moesif/) captures API traffic from [Kong API Gateway](https://getkong.org)
and logs it to [Moesif API Analytics](https://www.moesif.com). This plugin leverages an asynchronous design and doesn’t add any latency to your API calls.

- Kong is an open-source API gateway and middleware layer.
- Moesif is an API analytics and monitoring service.

This plugin supports automatic analysis of REST, GraphQL, and other APIs.

[Source Code on GitHub](https://github.com/Moesif/kong-plugin-moesif)

[Package on Luarocks](http://luarocks.org/modules/moesif/kong-plugin-moesif)

## How to install

> If you are using Kong's [Kubernetes Ingress Controller](https://github.com/Kong/kubernetes-ingress-controller), the installation is slightly different. Review the [docs for Kubernetes Ingress](https://www.moesif.com/docs/server-integration/kong-ingress-controller/).

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

After the luarock is installed, restart Kong before enabling the plugin

```bash
kong restart
```

### 4. Enable the Moesif plugin

```bash
curl -i -X POST --url http://localhost:8001/plugins/ --data "name=moesif" --data "config.application_id=YOUR_APPLICATION_ID";
```

### 5. Restart Kong again

If you don't see any logs in Moesif, you may need to restart Kong again. 

```bash
kong restart
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
and will be run on every request. Read the [Plugin Reference](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#add-plugin) and the
[Plugin Precedence](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#precedence) sections for more information.

```
curl -X POST http://localhost:8001/plugins \
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: Your Moesif Application Id can be found in the [_Moesif Portal_](https://www.moesif.com/).
After signing up for a Moesif account, your Moesif Application Id will be displayed during the onboarding steps. 

You can always find your Moesif Application Id at any time by logging 
into the [_Moesif Portal_](https://www.moesif.com/), click on the top right menu,
and then clicking _API Keys_.

### Enabling the plugin on a Service

Configure this plugin on a [Service](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#service-object) by making the following request on your Kong server:

```
curl -X POST http://kong:8001/services/{service}/plugins \
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _API Keys_
- `service`: the id or name of the Service that this plugin configuration will target.


### Enabling the plugin on a Route

Configure this plugin on a [Route](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#route-object) with:


```
curl -X POST http://kong:8001/routes/{route_id}/plugins \
    --data "name=moesif"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```
- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _API Keys_.
- `route_id`: the id of the Route that this plugin configuration will target.

### Enabling the plugin on a Consumer

You can use the `http://localhost:8001/plugins` endpoint to enable this plugin on specific [Consumers](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#consumer-object):

```
curl -X POST http://kong:8001/plugins \
    --data "name=moesif" \
    --data "consumer_id={consumer_id}"  \
    --data "config.application_id=MY_MOESIF_APPLICATION_ID"
```

- `config.application_id`: You can find your Moesif Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _API Keys_.
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
|config.api_version|1.0|API Version you want to tag this request with.|
|config.disable_capture_request_body|false|Disable logging of request body.|
|config.disable_capture_response_body|false|Disable logging of response body.|
|config.request_header_masks|{}|An array of request header fields to mask.|
|config.request_body_masks|{}|An array of request body fields to mask.|
|config.response_header_masks|{}|An array of response header fields to mask.|
|config.response_body_masks|{}|An array of response body fields to mask.|
|config.batch_size|200|Maximum batch size when sending to Moesif.|
|config.user_id_header||Request or response header to use for identifying the User. [See identifying users](#identifying-users).|
|config.company_id_header||Request or response header to use for identifying the Company. [See identifying companies](#identifying-companies).|
|config.authorization_header_name|authorization|Request header containing a `Bearer` or `Basic` token to extract user id. [See identifying users](#identifying-users). Also, supports a comma separated string. We will check headers in order like `"X-Api-Key,Authorization"`.|
|config.authorization_user_id_field|sub|Field name in JWT/OpenId token's payload for identifying users. Only applicable if `authorization_header_name` is set and is a `Bearer` token. [See identifying users](#identifying-users).|
|config.authorization_company_id_field|''|Field name in JWT/OpenId token's payload for identifying companies. Only applicable if `authorization_header_name` is set and is a `Bearer` token. [See identifying companies](#identifying-companies).|
|config.disable_gzip_payload_decompression|false|If set to true, will disable decompressing body in Kong.|
|config.max_callback_time_spent|2000|Limiter on how much time to send events to Moesif per worker cycle.|
|config.request_max_body_size_limit|100000|Maximum request body size in bytes to log.|
|config.response_max_body_size_limit|100000|Maximum response body size in bytes to log.|
|config.request_query_masks|{}|An array of query string params fields to mask.|
|config.event_queue_size|5000|Maximum number of events to hold in queue before sending to Moesif. In case of network issues when not able to connect/send event to Moesif, skips adding new to event to queue to prevent memory overflow.|
|config.debug|false|If set to true, prints internal log messages for debugging integration issues.|

## Updating config

If you need to update a configuration parameter, you must fetch and update the existing plugin instance.
Be careful not to call `POST http://localhost:8001/plugins/` again as this will create a duplicate instance of a plugin, which Kong does not support.

To update plugin config:

### 1. Retrieve the plugin instance id

Using the [GET /plugins](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#list-plugins), get the current instance id of the Moesif plugin.

```bash		
curl -X GET http://localhost:8001/plugins/
```
	
### 2. Update the plugin instance

Use the plugin id from the previous step, update the plugin with desired configuration using [PATCH /plugins/{plugin id}](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#update-plugin)
		
```bash
curl -X PATCH http://localhost:8001/plugins/{plugin id} 
    --data “config.application_id=YOUR_APPLICATION_ID” 
    --data “config.debug=true"
```

##  Identifying users

This plugin will automatically identify API users so you can associate API traffic to web traffic and create cross-platform funnel reports of your customer journey.
The default algorithm covers most authorization designs and works as follows:

1. If the `config.user_id_header` option is set, read the value from the specified HTTP header key `config.user_id_header`.
2. Else if Kong defined a value for `x-consumer-custom-id`, `x-consumer-username`, or `x-consumer-id` (in that order), use that value.
3. Else if an authorization token is present in `config.authorization_header_name`, parse the user id from the token as follows:
   * If header contains `Bearer`, base64 decode the string and use the value defined by `config.authorization_user_id_field` (by default is `sub`).
   * If header contains `Basic`, base64 decode the string and use the username portion (before the `:` character).

For advanced configurations, you can define a custom header containing the user id via `config.user_id_header` or override the options `config.authorization_header_name` and `config.authorization_user_id_field`.

## Identifying companies

You can associate API users to companies for tracking account-level usage. This can be done either:
1. Defining `config.company_id_header`, Moesif will use the value present in that header. 
2. Use the Moesif [update user API](https://www.moesif.com/docs/api#update-a-user) to set a `company_id` for a user. Moesif will associate the API calls automatically.
3. Else if an authorization token is present in `config.authorization_header_name`, parse the company id from the token as follows:
   * If header contains `Bearer`, base64 decode the string and use the value defined by `config.authorization_company_id_field` (by default is ``).

## Troubleshooting

### Duplicate key for `moesif` when enabling plugin
Kong only allows a single instance of a plugin enabled. This error message is shown when you already have Moesif enabled and trying to install a new instance of it.
If you're trying to update the config for Moesif, you need to update the existing instance by following [these instructions.](#updating-config)

### How to print debug logs

If you want to print Moesif debug logs, you can set `--data “config.debug=true"` when you enable the plugin.

If you already have Moesif installed, you must update the configuration of the existing instance and not install Moesif twice.
Otherwise, you will have multiple instances of a plugin installed, which Kong does not support.

To update existing plugin with debug option:

### 1. Retrieve the plugin instance id

Using the [GET /plugins](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#list-plugins), get the current instance id of the running Moesif plugin.

```bash		
curl -X GET http://localhost:8001/plugins/
```
	
### 2. Update the plugin instance

Use the plugin id from the previous step, update the plugin with your new configuration using [PATCH /plugins/{plugin id}](https://docs.konghq.com/gateway-oss/2.4.x/admin-api/#update-plugin). In this case, ensure `--data “config.debug=true"`
		
```bash
curl -X PATCH http://localhost:8001/plugins/{plugin id} 
    --data “config.application_id=YOUR_APPLICATION_ID” 
    --data “config.debug=true"
```

You should also set log_level to debug in `/etc/kong/kong.conf`. 

> If you need technical support from Moesif, attaching debug logs with your email to support can help shorten our resolution time. 

### No events logged to Moesif
You may have the plugin enabled twice for the same scope (global, service, route, etc), which Kong does not support.
Make sure you remove all instances of the Moesif plugin and re-enable it only once. To confirm if you are running into duplicate instances, you may see this in your Kong logs:

```
init.lua:394: insert(): ERROR: duplicate key value violates unique constraint "plugins_cache_key_key"
Key (cache_key)=(plugins:moesif::::) already exists., client: 127.0.0.1, server: kong_admin, request: "POST /plugins/ HTTP/1.1", host: "localhost:8001"
```

Another reason plugin may not be running is if you didn't restart Kong after enabling the plugin. Make sure you restart your Kong instance.

## Tested Version

For tested versions, [see this page](https://docs.konghq.com/hub/moesif/kong-plugin-moesif/) on Kong docs. 

## Examples

- [View example Dockerfile](https://github.com/Moesif/kong-docker-demo).

## Other integrations

To view more documentation on integration options, please visit __[the Integration Options Documentation](https://www.moesif.com/docs/getting-started/integration-options/).__
