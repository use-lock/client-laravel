<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lock\Laravel\Protocol\Http\Controllers\BackchannelLogoutController;
use Lock\Laravel\Protocol\Http\Controllers\OidcCallbackController;
use Lock\Laravel\Protocol\Http\Controllers\OidcLoginController;
use Lock\Laravel\Protocol\Http\Controllers\OidcLogoutController;

Route::get('login', OidcLoginController::class)->name('login')->middleware('web');
Route::get('login/callback', OidcCallbackController::class)->name('login.callback')->middleware('web');
Route::post('logout', OidcLogoutController::class)->name('logout')->middleware('web');

if (config('oidc-client.backchannel_logout.enabled', false)) {
    Route::post('oidc/backchannel-logout', BackchannelLogoutController::class)
        ->name('oidc.backchannel-logout')
        ->middleware('throttle:60,1');
}
