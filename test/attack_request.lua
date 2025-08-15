attacks = {
    "/api/users?id=1' OR '1'='1",  -- SQL injection
    "/api/search?q=<script>alert(1)</script>", -- XSS
    "/api/file?path=../../../etc/passwd" -- Directory traversal
 }
 
 request = function()
    path = attacks[math.random(#attacks)]
    return wrk.format("GET", path, {}, nil)
 end