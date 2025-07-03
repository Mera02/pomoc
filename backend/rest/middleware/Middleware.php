<?php

class Middleware {
    public static function check_auth() {
        // TODO: get headers, validate API-Key, halt if invalid
        $headers=getallheaders();

        if(!isset($headers['API-Key'])|| $headers['API-Key']!=='1234'){
            Flight::halt(401, json_encode([
                "error"=>"Unauthroized",
                "message"=>"Invalid API key or something"
            ]));
        }
    }
}
?>
