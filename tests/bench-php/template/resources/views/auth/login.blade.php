<form method="POST" action="/login">
  @csrf
  <input type="hidden" name="next" value="{{ request('next') }}">
  <input name="email" type="email"><input name="password" type="password">
  <button>Entra</button>
</form>
@if (request('msg'))
  <p class="notice">{!! request('msg') !!}</p>
@endif
