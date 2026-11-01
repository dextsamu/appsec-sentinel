<?php
namespace App\Providers;

use Illuminate\Support\Facades\Gate;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Gate::define('update-user', fn ($user) => in_array($user->role, ['ADMIN', 'RESPONSABILE', 'VOLONTARIO']));
    }
}
