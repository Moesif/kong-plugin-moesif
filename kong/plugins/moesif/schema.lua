return {
  fields = {
    api_endpoint = {required = true, type = "url", default = "https://api.moesif.net"},
    timeout = {default = 10000, type = "number"},
    keepalive = {default = 10000, type = "number"},
    api_version = {default = "1.0", type = "string"},
    application_id = {required = true, default ="", type="string"},
    disable_capture_request_body = {default = false, type = "boolean"},
    disable_capture_response_body = {default = false, type = "boolean"},
    request_masks = {default = {}, type = "array"},
    response_masks = {default = {}, type = "array"},
    batch_size = {default = 25, type = "number"},
    disable_transaction_id = {default = false, type = "boolean"},
  }
}
