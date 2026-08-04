@extends('security-guard::layouts.app')

@section('title', 'Blocked IP addresses')

@section('content')
    <h1>Blocked IP addresses</h1>

    @if (session('security-guard.status'))
        <p class="status">{{ session('security-guard.status') }}</p>
    @endif

    @if ($errors->any())
        <p class="status">{{ $errors->first() }}</p>
    @endif

    <form method="GET" class="filters">
        <label>
            <input type="checkbox" name="active" value="1" @checked($activeOnly)>
            Only currently blocked
        </label>
        <label>
            IP
            <input type="text" name="ip" value="{{ $ipFilter }}" placeholder="203.0.113.10">
        </label>
        <button type="submit">Filter</button>
    </form>

    <div class="table-wrap">
        <table>
            <thead>
            <tr>
                <th>State</th>
                <th>IP address</th>
                <th>Reason</th>
                <th>Pattern</th>
                <th>Requests</th>
                <th>Blocked at</th>
                <th>Last attempt</th>
                <th>Released at</th>
                <th></th>
            </tr>
            </thead>
            <tbody>
            @forelse ($records as $record)
                <tr>
                    <td>
                        <span class="badge {{ $record->isActive() ? 'badge-active' : 'badge-released' }}">
                            {{ $record->isActive() ? 'blocked' : 'released' }}
                        </span>
                    </td>
                    <td>{{ $record->ipAddress }}</td>
                    <td>{{ $record->reasonLabel() }}</td>
                    <td class="muted">{{ $record->matchedPattern ?? '-' }}</td>
                    <td>{{ $record->requestCount }}</td>
                    <td>{{ $record->blockedAt?->format('Y-m-d H:i:s') ?? '-' }}</td>
                    <td>{{ $record->lastAttemptedAt?->format('Y-m-d H:i:s') ?? '-' }}</td>
                    <td>{{ $record->releasedAt?->format('Y-m-d H:i:s') ?? '-' }}</td>
                    <td>
                        @if ($record->isActive())
                            <form method="POST" action="{{ route($routeNamePrefix.'blocked-ips.release') }}" class="inline">
                                @csrf
                                <input type="hidden" name="ip_address" value="{{ $record->ipAddress }}">
                                <button type="submit">Release</button>
                            </form>
                        @endif
                    </td>
                </tr>
            @empty
                <tr>
                    <td colspan="9" class="muted">No records.</td>
                </tr>
            @endforelse
            </tbody>
        </table>
    </div>

    @php($lastPage = (int) max(1, ceil($total / max(1, $perPage))))

    <p class="pagination">
        Page {{ $page }} of {{ $lastPage }} ({{ $total }} records)
        @if ($page > 1)
            &middot; <a href="{{ request()->fullUrlWithQuery(['page' => $page - 1]) }}">Previous</a>
        @endif
        @if ($page < $lastPage)
            &middot; <a href="{{ request()->fullUrlWithQuery(['page' => $page + 1]) }}">Next</a>
        @endif
    </p>
@endsection
