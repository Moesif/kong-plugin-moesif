return {
  fields = {
    api_endpoint = {required = true, type = "url", default = "https://api.moesif.net/v1/events"},
    timeout = {default = 10000, type = "number"},
    keepalive = {default = 10000, type = "number"},
    api_version = {default = "1.0", type = "string"},
    application_id = {required = true, default ="eyJhcHAiOiI0NjoxMiIsInZlciI6IjIuMCIsIm9yZyI6Ijg2OjgiLCJpYXQiOjE1MjQ2MTQ0MDB9.LqAVSvRpYBS_kAwN8AIOIjwSMbdVVcOaIFIDrSVaHMg", type="string"}
  }
}
