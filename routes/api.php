<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    Route::prefix('auth')->group(function () {
        // Login flow
        Route::post('/check-email-login', [AuthController::class, 'checkEmailForLogin']);
        Route::post('/login-pin', [AuthController::class, 'loginWithPin']);

        // Register flow
        Route::post('/check-email-register', [AuthController::class, 'checkEmailForRegister']);
        Route::post('/verify-otp', [AuthController::class, 'verifyOtp']);
        Route::post('/set-name', [AuthController::class, 'setName']);      // NEW
        Route::post('/set-pin', [AuthController::class, 'setPin']);        // NEW

        Route::middleware('auth:sanctum')->group(function () {
            Route::post('/logout', [AuthController::class, 'logout']);
            Route::get('/me', [AuthController::class, 'me']);
    });
});
});

