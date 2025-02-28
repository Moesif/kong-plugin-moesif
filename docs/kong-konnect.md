# Moesif Plugin for Kong Konnect

## Overview 
The Moesif plugin for Kong Konnect enables you to get powerful API analytics and observability directly within your Kong environment. It works by logging API traffic to [Moesif API Analytics and Monetization platform](https://www.moesif.com?language=kong-api-gateway&utm_medium=docs&utm_campaign=partners&utm_source=kong). 

- [Kong Konnect](https://docs.konghq.com/konnect/) is a cloud hosted API gateway and AI gateway.
- [Moesif](https://www.moesif.com/) is an API analytics and monetization service.

With the Moesif plugin for Kong Konnect, you can:

* [Understand customer API usage](https://www.moesif.com/features/api-analytics?utm_medium=docs&utm_campaign=partners&utm_source=kong)
* [Get alerted on API consumption and issues](https://www.moesif.com/features/api-monitoring?utm_medium=docs&utm_campaign=partners&utm_source=kong)
* [Monetize APIs with usage-based billing](https://www.moesif.com/solutions/metered-api-billing?utm_medium=docs&utm_campaign=partners&utm_source=kong)
* [Enforce quotas and limits](https://www.moesif.com/features/api-governance-rules?utm_medium=docs&utm_campaign=partners&utm_source=kong)
* [Guide customers using your APIs](https://www.moesif.com/features/user-behavioral-emails?utm_medium=docs&utm_campaign=partners&utm_source=kong)

This plugin is designed to log REST, GraphQL, XML/SOAP, and other API traffic without adding any latency. This integration supports both Kong Konnect via Docker and Kong Konnect via Kubernetes.

[Source Code on GitHub](https://github.com/Moesif/kong-plugin-moesif)

[Package on Luarocks](http://luarocks.org/modules/moesif/kong-plugin-moesif)

## How to install (Docker)

### 1. Add Moesif Plugin to Data Plane Node

1. In your control plane, go to `Data Plane Nodes`, then click `New Data Plane Node`.
2. Choose Linux (Docker) and Generate a certificate.
3. Copy the generated `docker run` command and add the following snippet to it:

   Substitute the `PATH_TO_DIR` in the snippet to the path where `kong-plugin-moesif` directory resides in your system.

   ```
   -v "/{PATH_TO_DIR}/kong:/tmp/custom_plugins/kong" \
   -e "KONG_PLUGINS=bundled,moesif" \
   -e "KONG_LUA_PACKAGE_PATH=/tmp/custom_plugins/?.lua;;" \
   ```

4. Run the command to start a data plane node with `Moesif` plugin loaded in.

Please note that if you are running Kong Konnect on Docker, the plugin needs to be installed inside the Kong Konnect container for each node. Mount the plugin’s source code into the container.


### 2. Enable Moesif plugin in Konnect

1. From the **Gateway Manager**, open a control plane.
2. Open Plugins from the side navigation, then click **Add Plugin**.
3. Open the **Custom Plugins** tab, then click **Create** on the _Custom Plugin_ tile.
4. Upload Schema File: `/kong/plugins/moesif/schema.lua` from the `kong-plugin-moesif` repo.
5. Open the Moesif plugin and add your Moesif Application Id. After signing up for a Moesif account, your Moesif Application Id will be displayed during the onboarding steps or by going to API keys section within Moesif settings.

## How to install (Kubernetes)

**Prerequisites**:
- `kubectl` or `oc` access: You have `kubectl` or `oc` (if working with OpenShift) installed and configured to communicate to your Kubernetes TLS.
- Helm 3 is installed.

### 1. Set up Helm

On your local machine, create a namespace in your Kubernetes cluster and pull down the Kong Helm repo.

1. Create a namespace:
   ```bash
   kubectl create namespace kong
   ```
2. Add the Kong charts repository:
   ```bash
   helm repo add kong https://charts.konghq.com
   ```
3. Update Helm:
   ```bash
   helm repo update
   ```


### 2. Create a ConfigMap with the Moesif Plugin Code

You'll need to clone the [kong-moesif-plugin](https://github.com/Moesif/kong-plugin-moesif) and navigate to the `kong/plugins` directory to create a configMap using 

```bash
kubectl create configmap kong-plugin-moesif --from-file=moesif -n kong
```
Please ensure that this is created in the same namespace as the one in which Kong is going to be installed. This step will add moesif-plugin to data plane nodes when Kong Konnect is created.


### 3. Enable Moesif plugin for control plane

Konnect requires the custom plugin’s `schema.lua` file. Using that file, it creates a plugin entry in the plugin catalog for your control plane.

1. From the **Gateway Manager**, open a control plane.
2. Open Plugins from the side navigation, then click **Add Plugin**.
3. Open the **Custom Plugins** tab, then click **Create** on the _Custom Plugin_ tile.
4. Upload the <a href="https://github.com/Moesif/kong-plugin-moesif/blob/master/kong/plugins/moesif/schema.lua" target="_blank" rel="noopener noreferrer">schema.lua file located on GitHub</a>.
5. Check that your file displays correctly in the preview, then click **Save**.
6. Open the newly saved plugin and add your Moesif Application Id. After signing up for a Moesif account, your Moesif Application Id will be displayed during the onboarding steps or by going to API keys section within Moesif settings.


Uploading a custom plugin schema adds the plugin to a specific control plane. If you need it to be available in multiple control planes, add the schema individually to each one.

### 4. Generate certificates

Generate the certificates Konnect requires through the UI, then copy and save them to your local machine as `tls.crt` and `tls.key`. Next create a Kubernetes secret containing the certificates that we will reference from the Helm chart `values.yaml`.

Create Secret using `tls.crt` and `.key` files:

```bash
kubectl create secret tls kong-cluster-cert -n kong --cert=/{PATH_TO_FILE}/tls.crt --key=/{PATH_TO_FILE}/tls.key
```

### 5. Load Moesif Plugin

With Helm, you could load the Moesif plugin by adding the following values to your `values.yaml` file:
```yaml
# values.yaml
plugins:
  configMaps:
  - name: kong-plugin-moesif
    pluginName: moesif
```


####  Example Configuration parameters for Gateway

Example `values.yaml` : Copy and paste this text into a file called `values.yaml` on your local machine. Please update `image.tag` if needed.

**Note**: moesif-plugin has been added in `plugins` section to load moesif-plugin in data plane nodes.

```yaml
# values.yaml
image:
  repository: kong/kong-gateway
  tag: '3.5.0.1'

secretVolumes:
  - kong-cluster-cert

admin:
  enabled: false

env:
  role: data_plane
  database: 'off'
  cluster_mtls: pki
  cluster_control_plane: 1820776ca7.us.cp0.konghq.com:443
  cluster_server_name: 1820776ca7.us.cp0.konghq.com
  cluster_telemetry_endpoint: 1820776ca7.us.tp0.konghq.com:443
  cluster_telemetry_server_name: 1820776ca7.us.tp0.konghq.com
  cluster_cert: /etc/secrets/kong-cluster-cert/tls.crt
  cluster_cert_key: /etc/secrets/kong-cluster-cert/tls.key
  lua_ssl_trusted_certificate: system
  konnect_mode: 'on'
  vitals: 'off'

# Add kong moesif plugin 
plugins:
  configMaps:
  - name: kong-plugin-moesif
    pluginName: moesif

ingressController:
  enabled: false
  installCRDs: false
```


### 6. Create Gateway
Apply the `values.yaml` with Helm install to deploy your Gateway data plane nodes:

```bash
helm install my-kong kong/kong -n kong --values ./values.yaml
```

You should see Gateway data plane pod up and in running state on success. To check pod's state, run the following:
```bash
kubectl get pods -n kong
```

## How to use

## Parameters

The Moesif Kong Plugin has a variety of options for things like data scrubbing and tweaking performance. 

|Parameter|Default(Kong gateway 1.x, 2.x)|Default(Kong gateway 3.x onwards) |Description|
|---|---|---|---|
|name|||The name of the plugin to use, in this case `moesif`|
|service_id|||The id of the Service which this plugin will target.|
|route_id	|||The id of the Route which this plugin will target.|
|enabled|true|true|Whether this plugin will be applied.|
|consumer_id|||The id of the Consumer which this plugin will target.|
|api_id|||The id of the API which this plugin will target. Note: The API Entity is deprecated in favor of Services since CE 0.13.0 and EE 0.32.|
|config.application_id	|||The Moesif application token provided to you by Moesif.|
|config.api_endpoint|https://api.moesif.net|https://api.moesif.net|URL for the Moesif API.|
|config.timeout (deprecated)|1000|1000|Timeout in milliseconds when connecting/sending data to Moesif.|
|config.connect_timeout|1000|1000|Timeout in milliseconds when connecting to Moesif.|
|config.send_timeout|5000|5000|Timeout in milliseconds when sending data to Moesif.|
|config.keepalive|5000|5000|Value in milliseconds that defines for how long an idle connection will live before being closed.|
|config.api_version|1.0|1.0|API Version you want to tag this request with.|
|config.disable_capture_request_body|false|false|Disable logging of request body.|
|config.disable_capture_response_body|false|false|Disable logging of response body.|
|config.request_header_masks|{}|{}|An array of request header fields to mask.|
|config.request_body_masks|{}|{}|An array of request body fields to mask.|
|config.response_header_masks|{}|{}|An array of response header fields to mask.|
|config.response_body_masks|{}|{}|An array of response body fields to mask.|
|config.batch_size|50|50|Maximum batch size when sending to Moesif.|
|config.user_id_header|''|nil|Request or response header to use for identifying the User. [See identifying users](#identifying-users).|
|config.company_id_header|''|nil|Request or response header to use for identifying the Company. [See identifying companies](#identifying-companies).|
|config.authorization_header_name|authorization|authorization|Request header containing a `Bearer` or `Basic` token to extract user id. [See identifying users](#identifying-users). Also, supports a comma separated string. We will check headers in order like `"X-Api-Key,Authorization"`.|
|config.authorization_user_id_field|sub|sub|Field name in JWT/OpenId token's payload for identifying users. Only applicable if `authorization_header_name` is set and is a `Bearer` token. [See identifying users](#identifying-users).|
|config.authorization_company_id_field|''|nil|Field name in JWT/OpenId token's payload for identifying companies. Only applicable if `authorization_header_name` is set and is a `Bearer` token. [See identifying companies](#identifying-companies).|
|config.disable_gzip_payload_decompression|false|false|If set to true, will disable decompressing body in Kong.|
|config.max_callback_time_spent|750|750|Limiter on how much time to send events to Moesif per worker cycle.|
|config.request_max_body_size_limit|100000|100000|Maximum request body size in bytes to log.|
|config.response_max_body_size_limit|100000|100000|Maximum response body size in bytes to log.|
|config.request_query_masks|{}|{}|An array of query string params fields to mask.|
|config.event_queue_size|100000|100000|Maximum number of events to hold in queue before sending to Moesif. In case of network issues when not able to connect/send event to Moesif, skips adding new to event to queue to prevent memory overflow.|
|config.debug|false|false|If set to true, prints internal log messages for debugging integration issues.|
|enable_compression|false|If set to true, requests are compressed before sending to Moesif.|

## Identifying users

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

### No events logged to Moesif
You may have the plugin enabled twice for the same scope (global, service, route, etc), which Kong does not support.
Make sure you remove all instances of the Moesif plugin and re-enable it only once. To confirm if you are running into duplicate instances, you may see this in your Kong logs:

```
init.lua:394: insert(): ERROR: duplicate key value violates unique constraint "plugins_cache_key_key"
Key (cache_key)=(plugins:moesif::::) already exists., client: 127.0.0.1, server: kong_admin, request: "POST /plugins/ HTTP/1.1", host: "localhost:8001"
```

Another reason plugin may not be running is if you didn't restart Kong after enabling the plugin. Make sure you restart your Kong instance.

### Kong Konnect fails to recognize customer_id as user_id for each API call

If you're using Kong Konnect with Moesif and having trouble linking the `customer_id` to `user_id` for API calls, it's likely related to authentication plugin configuration. Make sure you have the appropriate auth plugin enabled in Kong.

API keys must be correctly utilized, and it's important to note that API calls are only identified as linked to a user if the route is a protected one. If you've already sent requests using an API key generated via Kong but can't see them automatically linked to the customer ID, check your auth plugin settings.

## Examples

- [View example Dockerfile](https://github.com/Moesif/kong-docker-demo).

## Other integrations

To view more documentation on integration options, please visit __[the Integration Options Documentation](https://www.moesif.com/docs/getting-started/integration-options/).__
