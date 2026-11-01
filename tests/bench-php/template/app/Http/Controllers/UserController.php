<?php
namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

class UserController extends Controller
{
    public function show(int $id)
    {
        $me = Auth::user();
        return User::where('id', $id)->where('organization_id', $me->organization_id)->firstOrFail(['id', 'email', 'role']);
    }

    public function update(Request $request, int $id)
    {
        $me = Auth::user();
        if ($me->id !== $id && !in_array($me->role, ['ADMIN', 'RESPONSABILE'])) {
            abort(403);
        }
        $user = User::findOrFail($id);
        $user->update($request->all());
        return ['id' => $user->id];
    }

    public function resetPassword(int $id)
    {
        if (!Gate::allows('update-user')) {
            abort(403);
        }
        $target = User::findOrFail($id);
        $target->forceFill(['reset_token' => Str::random(64)])->save();
        return ['ok' => true];
    }

    public function destroy(int $id)
    {
        $admin = Auth::user();
        $target = User::where('id', $id)->where('organization_id', $admin->organization_id)->firstOrFail();
        abort_if($target->id === $admin->id, 400);
        $target->delete();
        return ['ok' => true];
    }
}
