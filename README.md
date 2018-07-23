# Moesif kong plugin

Moesif Kong plugin to integrate [Kong](https://getkong.org) with [Moesif](https://www.moesif.com).
It automatically captures _incoming_ API requests/responses and sends to Moesif for error analysis.

- Kong is an open source API gateway and management layer.
- Moesif is an API analytics and monitoring service.

[Source Code on GitHub](https://github.com/Moesif/kong-plugin-moesif)

[Package on Luarocks](http://luarocks.org/modules/abhijeetdhumal/kong-plugin-moesif)

## How to install

The .rock file is a self contained package that can be installed locally or from a remote server.

If the luarocks utility is installed in your system (this is likely the case if you used one of the official installation packages), you can install the 'rock' in your LuaRocks tree (a directory in which LuaRocks installs Lua modules).

It can be installed from luarocks repository by doing:

```shell
luarocks install kong-plugin-moesif
```

## How to use

How to configure kong moesif plugin:

### Enabling the plugin for a Service:

Configure on top of a Service by executing the following request on your Kong server:

```
curl -i -X POST --url http://localhost:8001/services/{service}/plugins/ \
     --data "name=moesif"   \
     --data "config.application_id=X-MOESIF-APPLICATION-ID";
```
service: the id or name of the Service that this plugin configuration will target.
X-MOESIF-APPLICATION-ID: You can find your Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_

### Enabling the plugin for a Route:

Configure on top of a Route with:


```
curl -X POST http://localhost:8001/routes/{route_id}/plugins \
    --data "name=moesif" \
    --data "config.application_id=X-MOESIF-APPLICATION-ID"
```
route_id: the id of the Route that this plugin configuration will target.
X-MOESIF-APPLICATION-ID: You can find your Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_


### Enabling the plugin for an API

If you are using the deprecated API entity, you can configure on top of an API by executing the following request on your Kong server:


```
$ curl -X POST http://kong:8001/apis/{api}/plugins \
    --data "name=moesif"  \
    --data "config.application_id=X-MOESIF-APPLICATION-ID"

```

api: either id or name of the API that this plugin configuration will target.
X-MOESIF-APPLICATION-ID: You can find your Application Id from [_Moesif Dashboard_](https://www.moesif.com/) -> _Top Right Menu_ -> _App Setup_


### Enabling the plugin for a Consumer

You can use the http://localhost:8001/plugins endpoint to target Consumers:

```
$ curl -X POST http://kong:8001/plugins \
    --data "name=moesif" \
    --data "consumer_id={consumer_id}"  \
    --data "config.application_id=X-MOESIF-APPLICATION-ID"
```
Where consumer_id is the id of the Consumer we want to associate with this plugin.

You can combine adding consumer_id and service_id in the same request.

### Global plugins

All plugins can be configured using the http:/kong:8001/plugins/ endpoint.
A plugin which is not associated to any API, Service, Route or Consumer is considered "global", and will be run on every request. Read the Plugin Reference and the Plugin Precedence sections for more information.

## Parameters

Here's a list of all the parameters which can be used in this plugin's configuration:

| Parameter | Default | Description |
| --- | --- | --- |
| name |  | The name of the plugin to use, in this case moesif |
| api_id |   | The id of the API which this plugin will target. |
| service_id | |The id of the Service which this plugin will target. |
| route_id	 | |The id of the Route which this plugin will target. |
| consumer_id |  | The id of the Consumer which this plugin will target. |
| config.application_id	 |  | Moesif application id  |
| config.api_endpoint | https://api.moesif.net | URL for the Moesif API.|
| config.timeout  | 10000  | An optional timeout in milliseconds when sending data to Moesif. |
| config.keepalive  | 30 |  An optional value in milliseconds that defines for how long an idle connection will live before being closed. |
| config.api_version| 1.0 | An optional API Version you want to tag this request with  |



## Other integrations

To view more more documentation on integration options, please visit __[the Integration Options Documentation](https://www.moesif.com/docs/getting-started/integration-options/).__
