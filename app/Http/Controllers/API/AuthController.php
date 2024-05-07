<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Throwable;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            $validate = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            if ($validate->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validate->errors()
                ], 401);
            }

            $credentials = $request->only('email', 'password');
            if (!Auth::attempt($credentials)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email and password didn\'t match our records.',
                ], 401);
            }

            $user = User::where('email', $request->email)->first();
            $token = $user->createToken('AuthToken')->plainTextToken;

            return response()->json([
                'status' => true,
                'message' => 'User successfully logged in',
                'token' => $token,
                'data' => $user
            ], 200);
        } catch (Throwable $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ], 401);
        }
    }

    public function isAuth(Request $request)
    {
        try {
            $auth = Auth::check();
            if (!$auth) {
                return response()->json([
                    'status' => false,
                    'message' => 'Unauthenticated'
                ], 401);
            }

            return response()->json([
                'status' => true,
                'message' => 'User is authenticated',
                'data' => Auth::user()
            ], 200);
        } catch (Throwable $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ], 401);
        }
    }

    public function logout(Request $request)
    {
        try {
            $user = User::where('id', $request->id)->first();
            $user->tokens()->delete();
            return response()->json([
                'status' => true,
                'message' => 'Successfully logged out',
            ], 200);
        } catch (Throwable $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ], 401);
        }
    }
}
