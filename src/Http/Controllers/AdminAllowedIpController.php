<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Http\Controllers;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminAllowedIpRecord;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Services\AllowlistRuleReview;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\View\View;

/**
 * Read-only view of who is allowed in from where.
 *
 * Deliberately has no write action. Granting administrative access is not
 * something a misconfigured `can:` rule should be able to hand out, so
 * changes stay in the CLI where they leave a shell history and require server
 * access. There is no route here that creates, edits, enables, disables or
 * deletes a rule.
 *
 * Nothing is joined onto the host's user table: `subject_type` and
 * `subject_id` are shown exactly as stored, so this screen cannot become a
 * roundabout way to read account attributes.
 */
class AdminAllowedIpController extends Controller
{
    public function __construct(
        private readonly AdminAllowedIpRepositoryContract $repository,
        private readonly AllowlistRuleReview $review,
        private readonly ConfigRepository $config,
    ) {}

    public function index(Request $request): View
    {
        $filters = $this->filters($request);

        $result = $this->repository->paginate(
            $filters,
            (int) $this->config->get('security-guard.management_ui.per_page', 50),
            max(1, (int) $request->integer('page', 1)),
        );

        return view('security-guard::admin-allowed-ips.index', [
            'rows' => $this->reviewed($result['items']),
            'total' => $result['total'],
            'page' => $result['page'],
            'perPage' => $result['per_page'],
            'filters' => $filters,
        ]);
    }

    /**
     * @param  array<int, AdminAllowedIpRecord>  $records
     * @return array<int, array{record: AdminAllowedIpRecord, kind: string, admits: string, warnings: array<int, string>}>
     */
    private function reviewed(array $records): array
    {
        // Duplicate detection spans every rule the subjects on this page have,
        // not just the page, so a duplicate split across pages is still shown.
        $subjects = [];

        foreach ($records as $record) {
            $subjects[$record->subjectType.'|'.$record->subjectId] = new AdminSubjectData(
                $record->subjectType,
                $record->subjectId,
            );
        }

        $counts = $this->repository->canonicalCounts(array_values($subjects));

        return array_map(
            fn (AdminAllowedIpRecord $record): array => ['record' => $record] + $this->review->review($record, $counts),
            $records,
        );
    }

    /**
     * @return array{subject_type: string|null, subject_id: string|null, ip: string|null, kind: string|null, enabled: bool|null}
     */
    private function filters(Request $request): array
    {
        $kind = $request->query('kind');
        $enabled = $request->query('enabled');

        return [
            'subject_type' => $this->text($request->query('subject_type')),
            'subject_id' => $this->text($request->query('subject_id')),
            'ip' => $this->text($request->query('ip')),
            'kind' => in_array($kind, ['exact', 'cidr'], true) ? $kind : null,
            'enabled' => match ($enabled) {
                '1' => true,
                '0' => false,
                default => null,
            },
        ];
    }

    private function text(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        // Bounded so a long query string cannot be used to probe the table.
        return $value === '' ? null : mb_substr($value, 0, 191);
    }
}
