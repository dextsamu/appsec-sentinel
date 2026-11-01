<?php
namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class TicketController extends Controller
{
    public function show(int $id)
    {
        $me = Auth::user();
        $ticket = DB::table('tickets')->where('id', $id)->where('organization_id', $me->organization_id)->first();
        abort_unless($ticket, 404);
        abort_if($me->role === 'VOLONTARIO' && $ticket->owner_id !== $me->id, 403);
        return response()->json($ticket);
    }
}
