<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class BasicAuthWithName
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
        $basicAuth = $request->header('Authorization');
        if(!empty($basicAuth)){
            try {
                $result = explode(" ", $basicAuth);
                $plainTextResult = explode(":", base64_decode($result[1]));
                $email = $plainTextResult[0];
                $password = $plainTextResult[1];
    
                if( Auth::attempt(['email' => $email, 'password' => $password])){
                    return $next($request);
                }
            } catch(\Throwable $e){

            }
        }

        return response()->json(null, 401);
    }
}
