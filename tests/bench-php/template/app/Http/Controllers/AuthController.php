<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function show() { return view('auth.login'); }

    public function login(Request $request)
    {
        $cred = $request->validate(['email' => 'required|email', 'password' => 'required']);
        if (!Auth::attempt($cred)) {
            return back()->withErrors(['email' => 'Credenziali non valide']);
        }
        $request->session()->regenerate();
        return redirect($request->input('next', '/dashboard'));
    }
}
