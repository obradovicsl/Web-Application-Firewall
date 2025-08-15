request = function()
    path = "/api/users?id=123"
    headers = {}
    headers["Content-Type"] = "application/json"
    return wrk.format("GET", path, headers, nil)
 end