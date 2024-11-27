# Moesif Plugin for Kong Ingress Controller

The [Moesif Kong plugin](https://docs.konghq.com/hub/moesif/kong-plugin-moesif/) captures API traffic from [Kong Ingress Controller](https://docs.konghq.com/kubernetes-ingress-controller/)
and logs it to [Moesif API Analytics](https://www.moesif.com). This plugin leverages an asynchronous design and doesn’t add any latency to your API calls.

- Kong is an open-source API gateway and middleware layer.
- Moesif is an API analytics and monitoring service.

This plugin supports automatic analysis of REST, GraphQL, and other APIs.

## How to Install

### Prerequisite
>- Make sure the `lua-zlib` lib dependencies (git, zlib1g-dev, gcc) have been installed on the system.
   >  - For example when using the apt package manager, run `apt-get update; apt-get install git zlib1g-dev gcc`.

### Create a ConfigMap with the Moesif Plugin Code

You'll need to clone the [kong-moesif-plugin](https://github.com/Moesif/kong-plugin-moesif){:target="_blank" rel="noopener"} and navigate to the `kong/plugins` directory to create a configMap using 

```bash
kubectl create configmap kong-plugin-moesif --from-file=moesif -n kong
```
Please ensure that this is created in the same namespace as the one in which Kong is going to be installed.

### Add Kong Chart

*Please Note* that this section assumes that you've helm kong chart available, if not please add kong helm chart. If you already have helm kong chart available, please skip this step.

You'll need to add the kong chart and update the repo via Helm.

```bash
# Add kong chart 
helm repo add kong https://charts.konghq.com

# Update helm repo
helm repo update
```
### Load Moesif Plugin

With Helm, you could load the Moesif plugin by adding the following values to your `values.yaml` file:

```yaml
# values.yaml
plugins:
  configMaps:
  - name: kong-plugin-moesif
    pluginName: moesif
```

### Deploy the Kubernetes Ingress Controller

You'll need to patch the kong ingress controller deployment with the Moesif plugin and rollout the deployment.

```bash
helm upgrade kong kong/kong --namespace kong --values values.yaml
```

### Enabling the plugin Globally

Create a `global-plugin.yaml` file

```yaml
apiVersion: configuration.konghq.com/v1
kind: KongClusterPlugin
metadata:
  name: moesif
  annotations:
    kubernetes.io/ingress.class: kong
  labels:
    global: "true"
config:
  application_id: Your Moesif Application Id
  debug: false
plugin: moesif
```

and then apply the plugin globally.

```bash
kubectl  apply -f global-plugin.yaml
```

Your Moesif Application Id can be found in the [_Moesif Portal_](https://www.moesif.com/).
After signing up for a Moesif account, your Moesif Application Id will be displayed during the onboarding steps. 

You can always find your Moesif Application Id at any time by logging 
into the [_Moesif Portal_](https://www.moesif.com/), click on the top right menu,
and then clicking _API Keys_.

*Please note* that setting the label global to "true" will apply the plugin globally in Kong, meaning it will be executed for every request that is proxied via Kong.

Please ensure that this is created in the same namespace as the one in which Kong is installed. If your namespace is different from `kong`, you should change this command accordingly.

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
|application_id	||The Moesif application token provided to you by Moesif.|
|api_endpoint|https://api.moesif.net|URL for the Moesif API.|
|timeout (deprecated)|1000|Timeout in milliseconds when connecting/sending data to Moesif.|
|connect_timeout|1000|Timeout in milliseconds when connecting to Moesif.|
|send_timeout|5000|Timeout in milliseconds when sending data to Moesif.|
|keepalive|5000|Value in milliseconds that defines for how long an idle connection will live before being closed.|
|api_version|1.0|API Version you want to tag this request with.|
|disable_capture_request_body|false|Disable logging of request body.|
|disable_capture_response_body|false|Disable logging of response body.|
|request_header_masks|{}|An array of request header fields to mask.|
|request_body_masks|{}|An array of request body fields to mask.|
|response_header_masks|{}|An array of response header fields to mask.|
|response_body_masks|{}|An array of response body fields to mask.|
|batch_size|50|Maximum batch size when sending to Moesif.|
|user_id_header||Request or response header to use for identifying the User. [See identifying users](#identifying-users).|
|company_id_header||Request or response header to use for identifying the Company. [See identifying companies](#identifying-companies).|
|authorization_header_name|authorization|Request header containing a `Bearer` or `Basic` token to extract user id. [See identifying users](#identifying-users). Also, supports a comma separated string. We will check headers in order like `"X-Api-Key,Authorization"`.|
|authorization_user_id_field|sub|Field name in JWT/OpenId token's payload for identifying users. Only applicable if `authorization_header_name` is set and is a `Bearer` token. [See identifying users](#identifying-users).|
|authorization_company_id_field|''|Field name in JWT/OpenId token's payload for identifying companies. Only applicable if `authorization_header_name` is set and is a `Bearer` token. [See identifying companies](#identifying-companies).|
|disable_gzip_payload_decompression|false|If set to true, will disable decompressing body in Kong.|
|max_callback_time_spent|2000|Limiter on how much time to send events to Moesif per worker cycle.|
|request_max_body_size_limit|100000|Maximum request body size in bytes to log.|
|response_max_body_size_limit|100000|Maximum response body size in bytes to log.|
|request_query_masks|{}|An array of query string params fields to mask.|
|event_queue_size|5000|Maximum number of events to hold in queue before sending to Moesif. In case of network issues when not able to connect/send event to Moesif, skips adding new to event to queue to prevent memory overflow.|
|debug|false|If set to true, prints internal log messages for debugging integration issues.|
|enable_compression|false|If set to true, requests are compressed before sending to Moesif.|


##  Identifying users

This plugin will automatically identify API users so you can associate API traffic to web traffic and create cross-platform funnel reports of your customer journey.
The default algorithm covers most authorization designs and works as follows:

1. If the `user_id_header` option is set, read the value from the specified HTTP header key `user_id_header`.
2. Else if Kong defined a value for `x-consumer-custom-id`, `x-consumer-username`, or `x-consumer-id` (in that order), use that value.
3. Else if an authorization token is present in `authorization_header_name`, parse the user id from the token as follows:
   * If header contains `Bearer`, base64 decode the string and use the value defined by `authorization_user_id_field` (by default is `sub`).
   * If header contains `Basic`, base64 decode the string and use the username portion (before the `:` character).

For advanced configurations, you can define a custom header containing the user id via `user_id_header` or override the options `authorization_header_name` and `authorization_user_id_field`.

## Identifying companies

You can associate API users to companies for tracking account-level usage. This can be done either:
1. Defining `company_id_header`, Moesif will use the value present in that header. 
2. Use the Moesif [update user API](https://www.moesif.com/docs/api#update-a-user) to set a `company_id` for a user. Moesif will associate the API calls automatically.
3. Else if an authorization token is present in `authorization_header_name`, parse the company id from the token as follows:
   * If header contains `Bearer`, base64 decode the string and use the value defined by `authorization_company_id_field` (by default is ``).

## Other integrations

To view more documentation on integration options, please visit __[the Integration Options Documentation](https://www.moesif.com/docs/getting-started/integration-options/).__
