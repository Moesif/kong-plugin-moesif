-- Morning Attempt 

local _M = {}
local helper = require "kong.plugins.moesif.helpers"
local HTTPS = "https"
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local session  -- This stores the SSL session for resumption
local sessionerr
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

    -- Perform SSL handshake if the URL scheme is HTTPS
    -- if parsed_url.scheme == HTTPS then
    --     -- Reuse SSL session if available for session resumption
    --     session, sessionerr = sock:sslhandshake(session, host, false, { reuse = true })
    --     if sessionerr then
    --         ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL handshake failed with " .. host .. ": " .. tostring(sessionerr))
    --         sock:close()
    --         return nil, sessionerr
    --     end
    -- end

    if parsed_url.scheme == HTTPS then
      ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  checking before handshake, session - ." .. dump(session) .." for pid - ".. ngx.worker.pid())

      -- if session then 
      --   ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE TRUE.")
      --   session, sessionerr = sock:sslhandshake(session, host, false)
      --   ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE TRUE, session - ." .. dump(session))
      --   ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE TRUE, sessionerr - ." .. dump(sessionerr))
      -- else 
      --   ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE FALSE.")
      --   session, sessionerr = sock:sslhandshake(true, host, false)
      --   ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE FALSE, session - ." .. dump(session))
      --   ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE FALSE, sessionerr - ." .. dump(sessionerr))
      -- end


      -- REVIEW
      if session == nil then 
        ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  REUSE EXISTING COONECTION." .." for pid - ".. ngx.worker.pid())
        -- session, sessionerr = sock:sslhandshake(true, host, false)
        session, sessionerr = sock:sslhandshake(session, host, false)
        -- ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE FALSE, session - ." .. dump(session))
        -- ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE FALSE, sessionerr - ." .. dump(sessionerr))
      else 
        ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  CREATE NEW CONNECTION." .." for pid - ".. ngx.worker.pid())
        -- reuseSession, sessionerr = sock:sslhandshake(false, host, false)
        session, sessionerr = sock:sslhandshake(nil, host, false)
        -- ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE TRUE, session - ." .. dump(session))
        -- ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE TRUE, reuseSession - ." .. dump(reuseSession))
        -- ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE TRUE, sessionerr - ." .. dump(sessionerr))
      end
  
      if sessionerr then
        if conf.debug then 
          ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": ", sessionerr)
        end
        sock:close()
        session = nil
        return nil, nil
      end
    end

    -- 10 mins REVIEW
    -- sock:setkeepalive(600000)
    -- sock:settimeout(conf.send_timeout)

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

        -- DEBUG
        -- -- Attempt to send a simple command to check if the socket is still valid
        -- local ok, err = sock:send("PING\r\n")  -- Example command, adjust as necessary
        -- if not ok then
        --     ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  Socket is INVALID !!!!!!!!!!!!!!, error: ", err .." for pid - ".. ngx.worker.pid())
        --     -- sock:close()  -- Close the invalid socket
        -- else
        --     ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK  Socket is VALID !!!!!!!!!!!!!!, ok: ", dump(ok) .." for pid - ".. ngx.worker.pid())
        -- end

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

    -- Perform SSL handshake if necessary (for HTTPS)
    -- if parsed_url.scheme == HTTPS then
    --     session, sessionerr = sock:sslhandshake(session, parsed_url.host, false, { reuse = true })
    --     if sessionerr then
    --         ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  Failed to do SSL handshake with " .. parsed_url.host .. ": " .. tostring(sessionerr))
    --         sock:close()
    --         return nil, nil
    --     end
    -- end

    -- if parsed_url.scheme == HTTPS then
    --   if session ~= nil then 
    --     ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE FALSE.")
    --     session, sessionerr = sock:sslhandshake(session, host, false)
    --   else 
    --     ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  SSL HANDSHAKE REUSE TRUE.")
    --     session, sessionerr = sock:sslhandshake(true, host, false)
    --   end
  
    --   if sessionerr then
    --     if conf.debug then 
    --       ngx_log(ngx_log_ERR, "[moesif] failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": ", sessionerr)
    --     end
    --     sock:close()
    --     session = nil
    --     return nil, nil
    --   end
    -- end

    -- ngx_log(ngx_log_ERR, "[moesif] MEMORYLEAK  ABOUT TO RELEASE CONN. NECESSARY?.")
    -- After using the connection, release it back to the pool for reuse
    -- release_connection(sock)

    sock:settimeout(10000)

    return sock, parsed_url
end

return _M
