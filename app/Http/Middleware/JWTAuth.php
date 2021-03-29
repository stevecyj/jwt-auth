<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Cache;

class JWTAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $bearerAuth = $request->header('Authorization');
        if(!empty($bearerAuth)){
            $jwtToken = explode(" ", $bearerAuth)[1];
            if ($this->validateJWToken($jwtToken)){
                $payload = $this->getPayload($jwtToken);
                if ($this->payloadValid($payload)){
                    $user = $this->getUser($payload);
                    if ($this->userTokenValid($payload, $user)){
                        Auth::login($user);
                        return $next($request);
                    }
                }
            }
        }

        return response()->json(['error' => 'jwt invalid.'], 401);
    }

    private function getPayload($token){
        $parts = explode('.', $token);
        $encoded_payload = $parts[1];
        return json_decode(
                $this->base64url_decode($encoded_payload),
                true
            );
    }

    private function getUser($payload){
        $user = $payload['user'];
        return User::find($user["id"]);
    }

    private function payloadValid($payload){
        $iat =  $payload['iat'];
        return (time() <= ($iat + 3600));
    }

    private function userTokenValid($payload, User $user){
        $user_token =  $payload['user_token'];
        $cached_user_token = Cache::get("user_token_{$user->id}");
        return $user_token == $cached_user_token;
    }

    private function validateJWToken($token){
        $parts = explode('.', $token);
        $encoded_headers = $parts[0];
        $encoded_payload = $parts[1];

        $key = env('JWT_KEY');
        $signature = $this->base64url_encode(
                hash_hmac('sha256',"$encoded_headers.$encoded_payload", $key, true )
            );
        return ($token == "$encoded_headers.$encoded_payload.$signature");
    }


    private function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64url_decode($token) {
        switch (strlen($token) % 4)
        {
            case 2:
                $token .= "==";
                break;
            case 3:
                $token .= "=";
                break;
        }

        return base64_decode(strtr($token, '-_', '+/'));
    }
}
