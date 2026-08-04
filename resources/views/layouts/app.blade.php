{{-- Minimal standalone layout. Publish the views (`security-guard-views`) and
     replace this with `@extends('your-admin-layout')` to blend the screen into
     an existing admin panel. --}}
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow">
    <title>@yield('title', 'Security Guard')</title>
    <style>
        :root { color-scheme: light dark; }
        body { margin: 0; padding: 2rem 1.5rem; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; line-height: 1.5; }
        h1 { font-size: 1.35rem; margin: 0 0 1.25rem; }
        table { border-collapse: collapse; width: 100%; font-size: .875rem; }
        th, td { padding: .5rem .625rem; border-bottom: 1px solid rgba(128,128,128,.3); text-align: left; white-space: nowrap; }
        th { font-weight: 600; }
        form.inline { display: inline; }
        .filters { margin-bottom: 1rem; display: flex; gap: .75rem; align-items: center; flex-wrap: wrap; }
        .status { padding: .625rem .875rem; margin-bottom: 1rem; border: 1px solid rgba(128,128,128,.4); border-radius: .25rem; }
        .badge { padding: .1rem .5rem; border-radius: 1rem; font-size: .75rem; border: 1px solid currentColor; }
        .badge-active { color: #b00020; }
        .badge-released { color: #4b7d4b; }
        .muted { opacity: .65; }
        .pagination { margin-top: 1rem; font-size: .875rem; }
        .table-wrap { overflow-x: auto; }
        button, input[type="text"] { font: inherit; padding: .3rem .6rem; }
    </style>
</head>
<body>
@yield('content')
</body>
</html>
