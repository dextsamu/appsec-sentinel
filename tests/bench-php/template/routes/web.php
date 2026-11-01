<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\QuoteController;
use App\Http\Controllers\DemoController;
use App\Http\Controllers\TicketController;

Route::get('/login', [AuthController::class, 'show'])->name('login');
Route::post('/login', [AuthController::class, 'login']);
Route::get('/health', fn () => response()->json(['status' => 'ok']));
Route::get('/quotes/{id}', [QuoteController::class, 'show']);
Route::post('/internal/demo-seed', [DemoController::class, 'seed']);

Route::middleware('auth')->group(function () {
    Route::get('/users/{id}', [UserController::class, 'show']);
    Route::patch('/users/{id}', [UserController::class, 'update']);
    Route::post('/users/{id}/reset-password', [UserController::class, 'resetPassword']);
    Route::get('/tickets/{id}', [TicketController::class, 'show']);
    Route::get('/debug/fix-org', [DemoController::class, 'fixOrg']);
    Route::delete('/admin/users/{id}', [UserController::class, 'destroy'])->middleware('role:ADMIN');
});
