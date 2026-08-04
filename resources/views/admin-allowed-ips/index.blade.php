@extends('security-guard::layouts.app')

@section('title', 'Administrative IP allowlist')

@section('content')
    <h1>Administrative IP allowlist</h1>

    {{-- Read-only on purpose: granting administrative access stays in the CLI,
         so there is no form here that writes anything. --}}
    <p class="muted">
        Read-only. Rules are changed with
        <code>security-guard:admin-ip:allow</code> and
        <code>security-guard:admin-ip:revoke</code>.
    </p>

    <form method="GET" class="filters">
        <label>
            Subject type
            <input type="text" name="subject_type" value="{{ $filters['subject_type'] }}" placeholder="admin">
        </label>
        <label>
            Subject id
            <input type="text" name="subject_id" value="{{ $filters['subject_id'] }}" placeholder="1234">
        </label>
        <label>
            Rule
            <input type="text" name="ip" value="{{ $filters['ip'] }}" placeholder="203.0.113.">
        </label>
        <label>
            Kind
            <select name="kind">
                <option value="">any</option>
                <option value="exact" @selected($filters['kind'] === 'exact')>Exact</option>
                <option value="cidr" @selected($filters['kind'] === 'cidr')>CIDR</option>
            </select>
        </label>
        <label>
            State
            <select name="enabled">
                <option value="">any</option>
                <option value="1" @selected($filters['enabled'] === true)>enabled</option>
                <option value="0" @selected($filters['enabled'] === false)>disabled</option>
            </select>
        </label>
        <button type="submit">Filter</button>
    </form>

    <div class="table-wrap">
        <table>
            <thead>
            <tr>
                <th>Subject type</th>
                <th>Subject id</th>
                <th>Rule</th>
                <th>Kind</th>
                <th>Admits</th>
                <th>Label</th>
                <th>State</th>
                <th>Created</th>
                <th>Updated</th>
            </tr>
            </thead>
            <tbody>
            @forelse ($rows as $row)
                @php($record = $row['record'])
                <tr>
                    <td>{{ $record->subjectType }}</td>
                    <td>{{ $record->subjectId }}</td>
                    <td><code>{{ $record->ipAddress }}</code></td>
                    <td>
                        @if ($row['kind'] === 'invalid')
                            <span class="badge badge-active">invalid</span>
                        @else
                            {{ $row['kind'] }}
                        @endif
                    </td>
                    <td>{{ $row['admits'] }}</td>
                    <td class="muted">{{ $record->label ?? '-' }}</td>
                    <td>
                        <span class="badge {{ $record->enabled ? 'badge-released' : 'badge-active' }}">
                            {{ $record->enabled ? 'enabled' : 'disabled' }}
                        </span>
                    </td>
                    <td>{{ $record->createdAt?->format('Y-m-d H:i:s') ?? '-' }}</td>
                    <td>{{ $record->updatedAt?->format('Y-m-d H:i:s') ?? '-' }}</td>
                </tr>
                @if ($row['warnings'] !== [])
                    {{-- A malformed row must not take the page down with it;
                         it is rendered with its finding attached instead. --}}
                    <tr>
                        <td colspan="9" class="muted">
                            @foreach ($row['warnings'] as $warning)
                                <div>⚠ {{ $warning }}</div>
                            @endforeach
                        </td>
                    </tr>
                @endif
            @empty
                <tr>
                    <td colspan="9" class="muted">No rules match.</td>
                </tr>
            @endforelse
            </tbody>
        </table>
    </div>

    @php($lastPage = (int) max(1, ceil($total / max(1, $perPage))))

    <p class="pagination">
        Page {{ $page }} of {{ $lastPage }} ({{ $total }} rules)
        @if ($page > 1)
            &middot; <a href="{{ request()->fullUrlWithQuery(['page' => $page - 1]) }}">Previous</a>
        @endif
        @if ($page < $lastPage)
            &middot; <a href="{{ request()->fullUrlWithQuery(['page' => $page + 1]) }}">Next</a>
        @endif
    </p>
@endsection
