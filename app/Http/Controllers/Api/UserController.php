<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Cache;

class UserController extends Controller
{
    public function login(Request $request){

        $user = $request->user();

        return response()->json([
            'user'=> $user,
            'jwt' => $this->getJWTToken($user)
        ]);
    }

    public function logout(Request $request){
        $user = $request->user();
        $user_token_key = "user_token_{$user->id}";
        $cached_user_token = time();
        Cache::put($user_token_key, $cached_user_token);
        return response()->json(null);
    }

    // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxMSwibmFtZSI6InR0IiwiZW1haWwiOiJ0dEBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkX2F0IjpudWxsLCJjcmVhdGVkX2F0IjoiMjAyMS0wMy0yOFQyMDozODowMy4wMDAwMDBaIiwidXBkYXRlZF9hdCI6IjIwMjEtMDMtMjhUMjA6Mzg6MDMuMDAwMDAwWiJ9LCJpYXQiOjE2MTcwMjk0MTIsInVzZXJfdG9rZW4iOjE2MTcwMjc4MDd9.JQeIrvZmBuMQWjZCHhzBfGmOiHvCk_hsnBxSe4_ROy8
    private function getJWTToken(User $user) {

        $user_token_key = "user_token_{$user->id}";
        if (Cache::has($user_token_key)){
            $cached_user_token = Cache::get($user_token_key);
        } else {
            $cached_user_token = time();
            Cache::put($user_token_key, $cached_user_token);
        }

        $headers = ['alg'=>'HS256','typ'=>'JWT'];
        $payload = ["user"=> $user, "iat" => time(), 'user_token' => $cached_user_token];
        $encoded_headers = $this->base64url_encode(json_encode($headers));
        $encoded_payload = $this->base64url_encode(json_encode($payload));
        $key = env('JWT_KEY');
        $signature = $this->base64url_encode(
                hash_hmac('sha256',"$encoded_headers.$encoded_payload", $key, true )
            );
        return "$encoded_headers.$encoded_payload.$signature";
    }

    private function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
