return {
  fields = {
    api_endpoint = {required = true, type = "url", default = "https://api.moesif.net/v1/events"},
    timeout = {default = 10000, type = "number"},
    keepalive = {default = 10000, type = "number"},
    api_version = {default = "1.0", type = "string"},
    application_id = {required = true, default ="", type="string"},
    sampling_percentage = {default = 100, type = "number"},
    disable_capture_request_body = {default = false, type = "boolean"},
    disable_capture_response_body = {default = false, type = "boolean"},
    request_masks = {default = {}, type = "array"},
    response_masks = {default = {}, type = "array"}
  }
}
