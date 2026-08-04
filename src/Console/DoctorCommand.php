<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Data\DiagnosticResult;
use Apkk\LaravelSecurityGuard\Services\ConfigurationDoctor;
use Illuminate\Console\Command;

class DoctorCommand extends Command
{
    protected $signature = 'security-guard:doctor
        {--json : Emit machine-readable JSON instead of a table}
        {--strict : Treat warnings as failures}';

    protected $description = 'Check the security-guard configuration before enabling a module';

    /**
     * Exit codes are the contract for deployment pipelines:
     * 0 healthy, 1 failure, 2 warnings under --strict.
     */
    public const EXIT_WARNINGS = 2;

    public function handle(ConfigurationDoctor $doctor): int
    {
        $results = $doctor->run();

        $failures = array_values(array_filter($results, fn (DiagnosticResult $r): bool => $r->isFailure()));
        $warnings = array_values(array_filter($results, fn (DiagnosticResult $r): bool => $r->isWarning()));
        $strict = (bool) $this->option('strict');

        $exitCode = match (true) {
            $failures !== [] => self::FAILURE,
            $strict && $warnings !== [] => self::EXIT_WARNINGS,
            default => self::SUCCESS,
        };

        if ((bool) $this->option('json')) {
            $this->renderJson($results, $failures, $warnings, $strict, $exitCode);

            return $exitCode;
        }

        $this->renderTable($results, $failures, $warnings, $strict);

        return $exitCode;
    }

    /**
     * @param  array<int, DiagnosticResult>  $results
     * @param  array<int, DiagnosticResult>  $failures
     * @param  array<int, DiagnosticResult>  $warnings
     */
    private function renderJson(
        array $results,
        array $failures,
        array $warnings,
        bool $strict,
        int $exitCode,
    ): void {
        // Written with the plain output buffer, not the styled one, so the
        // document stays parseable when the command is piped.
        $this->output->writeln((string) json_encode([
            'healthy' => $exitCode === self::SUCCESS,
            'strict' => $strict,
            'exit_code' => $exitCode,
            'summary' => [
                'total' => count($results),
                'executed' => count(array_filter(
                    $results,
                    static fn (DiagnosticResult $r): bool => $r->wasExecuted(),
                )),
                'skipped' => count(array_filter(
                    $results,
                    static fn (DiagnosticResult $r): bool => ! $r->wasExecuted(),
                )),
                'failures' => count($failures),
                'warnings' => count($warnings),
            ],
            'results' => array_map(
                static fn (DiagnosticResult $r): array => $r->toArray(),
                $results,
            ),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /**
     * @param  array<int, DiagnosticResult>  $results
     * @param  array<int, DiagnosticResult>  $failures
     * @param  array<int, DiagnosticResult>  $warnings
     */
    private function renderTable(array $results, array $failures, array $warnings, bool $strict): void
    {
        $this->table(
            ['', 'Check', 'Detail'],
            array_map(static fn (DiagnosticResult $r): array => [
                match ($r->severity) {
                    DiagnosticResult::OK => '<fg=green>PASS</>',
                    DiagnosticResult::WARNING => '<fg=yellow>WARN</>',
                    DiagnosticResult::FAILURE => '<fg=red>FAIL</>',
                    // No severity means the check never ran.
                    default => '<fg=gray>SKIP</>',
                },
                $r->check,
                $r->message,
            ], $results),
        );

        foreach ([...$failures, ...$warnings] as $result) {
            if ($result->remedy === null) {
                continue;
            }

            $this->newLine();
            $this->line(sprintf(
                '<fg=%s>%s</> %s',
                $result->isFailure() ? 'red' : 'yellow',
                strtoupper((string) $result->severity),
                $result->check,
            ));
            $this->line('  '.$result->message);
            $this->line('  <fg=cyan>→</> '.$result->remedy);

            foreach ($result->context as $key => $value) {
                $this->line("  <fg=gray>{$key}: {$value}</>");
            }
        }

        $this->newLine();

        if ($failures !== []) {
            $this->components->error(sprintf(
                '%d check(s) failed, %d warning(s).',
                count($failures),
                count($warnings),
            ));

            return;
        }

        if ($warnings !== []) {
            $strict
                ? $this->components->error(count($warnings).' warning(s), failing because --strict was given.')
                : $this->components->warn(count($warnings).' warning(s). Review before production.');

            return;
        }

        $this->components->info('All checks passed.');
    }
}
