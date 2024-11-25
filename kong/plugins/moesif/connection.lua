local _M = {}
local helper = require "kong.plugins.moesif.helpers"
local HTTPS = "https"
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local session  -- This stores the SSL session for resumption
local sessionerr
-- local session_cache = {}
local reuseSession

-- Connection pool to hold reusable sockets
local connection_pool = {}
local max_pool_size = 10  -- Max number of connections in the pool
local max_retries = 3  -- Max retries for acquiring a connection
-- local global_socket_timeout = 1000  -- Timeout for socket connections (in milliseconds)


function dump(o)
  if type(o) == 'table' then
     local s = '{ '
     for k,v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ','
     end
     return s .. '} '
  else
     return tostring(o)
  end
end

-- Create a new connection or use an existing one from the pool
local function create_connection(api_endpoint, url_path, conf)
    local parsed_url = helper.parse_url(api_endpoint..url_path)
    local host = parsed_url.host
    local port = tonumber(parsed_url.port)
    
    -- Create a new socket object
    local sock = ngx.socket.tcp()
    sock:settimeout(2000)  -- conf.connect_timeout -- socket creation timeout 
    -- sock:settimeout(global_socket_timeout)

    -- Try connecting to the server
    local ok, err = sock:connect(host, port)
    if not ok then
        ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  Failed to connect to " .. host .. ":" .. tostring(port) .. ": ", err .." for pid - ".. ngx.worker.pid())
        return nil, err
    end

    if parsed_url.scheme == HTTPS then
      -- local ssl_session = session_cache[host .. ":" .. port]
      ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  GOT SESSION FROM THE CACHE ---- - ." .. dump(ssl_session) .." for pid - ".. ngx.worker.pid())

      if session ~= nil then 
        ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  REUSE EXISTING COONECTION." .." for pid - ".. ngx.worker.pid())
        session, sessionerr = sock:sslhandshake(session, host, false)
      else 
        ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  CREATE NEW CONNECTION." .." for pid - ".. ngx.worker.pid())
        session, sessionerr = sock:sslhandshake(true, host, false)
        --   -- Store the session for future reuse
      --   -- session_cache[host .. ":" .. port] = session
      end
    end

    if sessionerr then
      if conf.debug then 
        ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": ", sessionerr)
      end
      sock:close()
      session = nil
      return nil, nil
    end

    sock:setoption("keepalive", true)

    return sock, parsed_url
end

-- Acquire a connection from the pool or create a new one if none are available
local function acquire_connection(api_endpoint, url_path, conf)
    -- Check if there is an available connection in the pool
    ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  Trying to acquire connection with connection in the pool - ." .. tostring(#connection_pool) .." for pid - ".. ngx.worker.pid())

    if #connection_pool > 0 then
        -- Reuse an existing connection from the pool
        local sock = table.remove(connection_pool)
        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  ACQUIRED CONNECTION existing connection from the pool." .." for pid - ".. ngx.worker.pid())

        -- CHECK IF CONNECTION IS ACTIVE, REFRESH
        local count, readErr = sock:getreusedtimes()
        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK getreusedtimes." .. " count - " .. dump(count) .. "readErr - " .. dump(readErr) .." for pid - ".. ngx.worker.pid())
        if count ~= nil and count > 0 then 
          ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  REUSED connection from the pool." .. " getreusedtimes count - " .. tostring(count) .." for pid - ".. ngx.worker.pid())
          return sock, helper.parse_url(api_endpoint..url_path)
        else 

          ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  CLOSING existing connection from the pool." .." for pid - ".. ngx.worker.pid())
          -- sock:close()

        end
    end

    -- If no available connections, create a new one
    local retries = 0
    local sock, err
    while retries < max_retries do
        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  NO CONNECTION AVAILABLE IN POOL, CREATING NEW ." .." for pid - ".. ngx.worker.pid())
        sock, err = create_connection(api_endpoint, url_path, conf)
        if sock then
            return sock, helper.parse_url(api_endpoint..url_path)
        end
        retries = retries + 1
        ngx.sleep(0.5)  -- Small delay before retrying
    end

    ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  Failed to acquire a connection after retries.")
    return nil, err
end

-- Release a connection back into the pool
function _M.release_connection(sock)
    ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  Trying to RELEASE connection with connection in the pool - ." .. tostring(#connection_pool))
    -- Only add the connection to the pool if the pool size is not exceeded
    if #connection_pool < max_pool_size then
        sock:setoption("keepalive", true)  
        sock:setkeepalive(600000)
        table.insert(connection_pool, sock)
        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  Connection added to pool. Pool size: " .. #connection_pool)
    else
        sock:close()
        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  Pool full, closing socket.")
    end
end

-- Main function to get a connection and perform the handshaking if necessary
function _M.get_connection(api_endpoint, url_path, conf)
    -- Try to acquire a connection from the pool (or create a new one)
    local sock, parsed_url = acquire_connection(api_endpoint, url_path, conf)
    if not sock then
        ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  Failed to acquire socket connection.")
        return nil, nil
    end

    sock:settimeout(10000)

    return sock, parsed_url
end

return _M

