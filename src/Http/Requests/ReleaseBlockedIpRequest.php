<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ReleaseBlockedIpRequest extends FormRequest
{
    /**
     * Authorisation belongs to the route middleware the host configures
     * (`can:manage-security` by default), which has already run by this point.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return [
            'ip_address' => ['required', 'string', 'ip'],
        ];
    }
}
