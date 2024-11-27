local typedefs = require "kong.db.schema.typedefs"

return {
  name = "moesif",
  fields = {
    {
      consumer = typedefs.no_consumer
    },
    {
      protocols = typedefs.protocols_http
    },
    {
      config = {
        type = "record",
        fields = {
          {
            api_endpoint = {required = true, type = "string", default = "https://api.moesif.net"}
          },
          {
            timeout = {default = 1000, type = "number"}
          },
          {
            connect_timeout = {default = 1000, type = "number"}
          },
          {
            send_timeout = {default = 5000, type = "number"}
          },
          {
            keepalive = {default = 5000, type = "number"}
          },
          {
            event_queue_size = {default = 1000000, type = "number"}
          },
          {
            api_version = {default = "1.0", type = "string"}
          },
          {
            application_id = {required = true, default = nil, type="string"}
          },
          {
            disable_capture_request_body = {default = false, type = "boolean"}
          },
          {
            disable_capture_response_body = {default = false, type = "boolean"}
          },
          {
            request_masks = {default = {}, type = "array", elements = typedefs.header_name}
          },
          {
            request_body_masks = {default = {}, type = "array", elements = typedefs.header_name}
          },
          {
            request_header_masks = {default = {}, type = "array", elements = typedefs.header_name}
          },
          {
            response_masks = {default = {}, type = "array", elements = typedefs.header_name}
          },
          {
            response_body_masks = {default = {}, type = "array", elements = typedefs.header_name}
          },
          {
            response_header_masks = {default = {}, type = "array", elements = typedefs.header_name}
          },
          {
            batch_size = {default = 50, type = "number", elements = typedefs.header_name}
          },
          {
            disable_transaction_id = {default = false, type = "boolean"}
          },
          {
            debug = {default = false, type = "boolean"}
          },
          {
            disable_gzip_payload_decompression = {default = false, type = "boolean"}
          },
          {
            user_id_header = {default = nil, type = "string"}
          },
          {
            authorization_header_name = {default = "authorization", type = "string"}
          },
          {
            authorization_user_id_field = {default = "sub", type = "string"}
          },
          {
            authorization_company_id_field = {default = nil, type = "string"}
          },
          {
            company_id_header = {default = nil, type = "string"}
          },
          {
            max_callback_time_spent = {default = 750, type = "number"}
          },
          {
            request_max_body_size_limit = {default = 100000, type = "number"}
          },
          {
            response_max_body_size_limit = {default = 100000, type = "number"}
          },
          {
            request_query_masks = {default = {}, type = "array", elements = typedefs.header_name}
          },
          {
            -- TODO Change it to enable_compression default to false
            disable_moesif_payload_compression = {default = true, type = "boolean"}
          },
        },
      },
    },
  },
  entity_checks = {}
}
