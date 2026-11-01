<?php
namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class QuoteController extends Controller
{
    public function show(string $id)
    {
        $quote = DB::select("SELECT q.*, o.name AS org_name, o.iban FROM quotes q JOIN organizations o ON o.id = q.organization_id WHERE q.id = $id");
        return $quote ? response()->json($quote[0]) : abort(404);
    }
}
