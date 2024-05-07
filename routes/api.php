<?php

use App\Http\Controllers\API\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('login', [AuthController::class, 'login']);

Route::group(['middleware' => 'auth:sanctum'], function () {
    Route::get('auth-check', [AuthController::class, 'isAuth']);
    Route::post('logout', [AuthController::class, 'logout']);
});
