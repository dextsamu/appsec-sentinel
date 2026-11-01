<?php
namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class DemoController extends Controller
{
    public function seed()
    {
        $org = DB::table('organizations')->where('slug', 'sezione-principale')->first();
        abort_unless($org, 404);
        $created = [];
        foreach (['RESPONSABILE', 'VOLONTARIO'] as $role) {
            $created[] = User::create(['email' => strtolower($role) . '.demo@example.org', 'password' => Hash::make('Demo2024!'), 'role' => $role, 'organization_id' => $org->id])->email;
        }
        return ['created' => $created];
    }

    public function fixOrg()
    {
        DB::table('organizations')->where('slug', 'sezione-principale')->update(['name' => 'Sezione Principale']);
        return ['ok' => true];
    }
}
