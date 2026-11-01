<?php
Route::get('/health', fn() => 'ok');
Route::post('/orders', [OrderController::class, 'store'])->middleware('auth');
Route::delete('/admin/users/{id}', [AdminController::class, 'destroy']);
