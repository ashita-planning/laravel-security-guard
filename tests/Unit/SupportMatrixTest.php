<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Support\SupportedVersions;
use Composer\Semver\Semver;
use PHPUnit\Framework\TestCase;

/**
 * composer.json, the CI matrix and the README support table have to agree.
 *
 * These three drift apart quietly: a constraint gets widened without a CI cell
 * to prove it, or a cell is removed while the README still advertises it. For
 * a package whose support policy is tied to upstream security-fix windows,
 * that drift is the difference between a claim and a fact, so it is asserted
 * rather than reviewed by eye.
 */
class SupportMatrixTest extends TestCase
{
    private const ROOT = __DIR__.'/../..';

    /**
     * Sample versions used to prove a major is or is not accepted.
     * The low sample sits below the advisory-safe floor on purpose.
     */
    private const LARAVEL_SAMPLES = [
        '10' => ['10.0.0', '10.50.2'],
        '11' => ['11.0.0', '11.55.0'],
        '12' => ['12.61.1', '12.64.0'],
        '13' => ['13.12.0', '13.23.0'],
    ];

    /**
     * @return array<string, mixed>
     */
    private function composerJson(): array
    {
        $decoded = json_decode((string) file_get_contents(self::ROOT.'/composer.json'), true);

        $this->assertIsArray($decoded);

        return $decoded;
    }

    private function workflow(): string
    {
        return (string) file_get_contents(self::ROOT.'/.github/workflows/tests.yml');
    }

    private function readme(): string
    {
        return (string) file_get_contents(self::ROOT.'/README.md');
    }

    /**
     * @return array<int, array{php: string, laravel: string, testbench: string}>
     */
    private function matrixRows(): array
    {
        preg_match_all(
            "/- \{ php: '([^']+)', laravel: '([^']+)', testbench: '([^']+)'/",
            $this->workflow(),
            $matches,
            PREG_SET_ORDER,
        );

        return array_map(static fn (array $m): array => [
            'php' => $m[1],
            'laravel' => $m[2],
            'testbench' => $m[3],
        ], $matches);
    }

    private function illuminateConstraint(): string
    {
        $require = $this->composerJson()['require'];
        $constraints = [];

        foreach ($require as $package => $constraint) {
            if (str_starts_with((string) $package, 'illuminate/')) {
                $constraints[] = $constraint;
            }
        }

        $this->assertNotEmpty($constraints, 'No illuminate/* requirements found.');
        $this->assertCount(
            1,
            array_unique($constraints),
            'Every illuminate/* component must carry the same constraint.',
        );

        return (string) $constraints[0];
    }

    /**
     * Skip when composer.json is not the committed one.
     *
     * Each matrix cell pins a single Laravel and Testbench version into the
     * manifest before installing, so inside those jobs `require-dev` describes
     * that one cell rather than the package's real support range. Comparing the
     * whole matrix against it would report a contradiction that does not exist.
     * The package never declares laravel/framework itself, so its presence in
     * require-dev is a reliable marker that CI rewrote the file.
     */
    private function requirePristineManifest(): void
    {
        $devRequire = $this->composerJson()['require-dev'] ?? [];

        if (isset($devRequire['laravel/framework'])) {
            $this->markTestSkipped('composer.json was pinned by the CI matrix; checked in the unpinned jobs.');
        }
    }

    public function test_the_ci_matrix_is_not_empty(): void
    {
        $this->assertNotEmpty($this->matrixRows(), 'The CI matrix could not be parsed.');
    }

    public function test_every_laravel_major_in_ci_is_allowed_by_the_constraint(): void
    {
        $constraint = $this->illuminateConstraint();

        foreach ($this->matrixRows() as $row) {
            $major = rtrim($row['laravel'], '.*');
            $samples = self::LARAVEL_SAMPLES[$major] ?? null;

            $this->assertNotNull($samples, "No sample versions defined for Laravel {$major}.");

            foreach ($samples as $version) {
                $this->assertTrue(
                    Semver::satisfies($version, $constraint),
                    "CI tests Laravel {$version} but the constraint {$constraint} rejects it.",
                );
            }
        }
    }

    public function test_unsupported_majors_are_rejected_by_the_constraint(): void
    {
        $constraint = $this->illuminateConstraint();

        // Laravel 10 and 11 are past their upstream security-fix windows.
        foreach (['10', '11'] as $major) {
            foreach (self::LARAVEL_SAMPLES[$major] as $version) {
                $this->assertFalse(
                    Semver::satisfies($version, $constraint),
                    "Laravel {$version} is out of support but {$constraint} still accepts it.",
                );
            }
        }
    }

    public function test_the_constraint_floor_excludes_advisory_affected_releases(): void
    {
        $constraint = $this->illuminateConstraint();

        // The oldest release of each line that clears Composer's advisory
        // policy. Anything below is installable only with the check disabled.
        $this->assertFalse(Semver::satisfies('12.61.0', $constraint));
        $this->assertTrue(Semver::satisfies('12.61.1', $constraint));
        $this->assertFalse(Semver::satisfies('13.11.0', $constraint));
        $this->assertTrue(Semver::satisfies('13.12.0', $constraint));
    }

    public function test_the_doctor_floors_match_the_composer_constraint(): void
    {
        $constraint = $this->illuminateConstraint();

        // The doctor tells operators their Laravel is too old. If its floors
        // drifted from the manifest it would either wave through an install
        // Composer will refuse, or reject one that is perfectly fine.
        foreach (SupportedVersions::majors() as $major) {
            $floor = (string) SupportedVersions::floorFor($major);

            $this->assertTrue(
                Semver::satisfies($floor, $constraint),
                "SupportedVersions floor {$floor} is not permitted by {$constraint}.",
            );

            $this->assertSame(
                $major,
                explode('.', $floor)[0],
                "The floor registered for Laravel {$major} is a {$floor} version.",
            );
        }

        $ciMajors = array_unique(array_map(
            static fn (array $row): string => rtrim($row['laravel'], '.*'),
            $this->matrixRows(),
        ));

        $this->assertSame(
            array_values($ciMajors),
            array_values(SupportedVersions::majors()),
            'SupportedVersions and the CI matrix disagree on which majors are supported.',
        );
    }

    public function test_every_supported_major_declares_a_security_support_end_date(): void
    {
        foreach (SupportedVersions::majors() as $major) {
            $ends = SupportedVersions::supportEndsFor($major);

            $this->assertNotNull($ends, "Laravel {$major} has no security support end date.");
            $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $ends);
        }
    }

    public function test_every_php_version_in_ci_is_allowed_by_the_constraint(): void
    {
        $constraint = (string) $this->composerJson()['require']['php'];

        foreach ($this->matrixRows() as $row) {
            $this->assertTrue(
                Semver::satisfies($row['php'].'.0', $constraint),
                "CI tests PHP {$row['php']} but the constraint {$constraint} rejects it.",
            );
        }
    }

    public function test_no_ci_cell_pairs_laravel_13_with_php_below_8_3(): void
    {
        foreach ($this->matrixRows() as $row) {
            if ($row['laravel'] !== '13.*') {
                continue;
            }

            $this->assertTrue(
                version_compare($row['php'], '8.3', '>='),
                "Laravel 13 requires PHP 8.3+, but a cell pairs it with PHP {$row['php']}.",
            );
        }
    }

    public function test_every_testbench_major_in_ci_is_allowed_by_the_dev_constraint(): void
    {
        $this->requirePristineManifest();

        $constraint = (string) $this->composerJson()['require-dev']['orchestra/testbench'];

        foreach ($this->matrixRows() as $row) {
            $version = rtrim($row['testbench'], '.*').'.0.0';

            $this->assertTrue(
                Semver::satisfies($version, $constraint),
                "CI installs testbench {$row['testbench']} but {$constraint} rejects it.",
            );
        }
    }

    public function test_both_supported_majors_are_covered_at_their_lowest_dependencies(): void
    {
        $lowest = [];

        foreach ($this->matrixRows() as $row) {
            if (str_contains($this->workflow(), "laravel: '{$row['laravel']}', testbench: '{$row['testbench']}', dependencies: 'lowest'")) {
                $lowest[] = $row['laravel'];
            }
        }

        // --prefer-lowest is what proves the constraint floor is real.
        $this->assertContains('12.*', $lowest);
        $this->assertContains('13.*', $lowest);
    }

    public function test_the_readme_advertises_exactly_the_majors_ci_proves(): void
    {
        $readme = $this->readme();

        $ciMajors = array_unique(array_map(
            static fn (array $row): string => rtrim($row['laravel'], '.*'),
            $this->matrixRows(),
        ));

        foreach ($ciMajors as $major) {
            $this->assertMatchesRegularExpression(
                "/\|\s*{$major}\.x\s*\|[^|]*\|\s*正式対応\s*\|/u",
                $readme,
                "README does not list Laravel {$major}.x as supported.",
            );
        }

        foreach (['10', '11'] as $major) {
            $this->assertMatchesRegularExpression(
                "/\|\s*{$major}\.x\s*\|[^|]*\|\s*対応対象外\s*\|/u",
                $readme,
                "README does not mark Laravel {$major}.x as unsupported.",
            );
        }
    }

    public function test_the_readme_header_matches_the_php_constraint(): void
    {
        $constraint = (string) $this->composerJson()['require']['php'];

        $this->assertStringContainsString(
            "PHP `{$constraint}`",
            $this->readme(),
            'The README header advertises a different PHP constraint.',
        );
    }

    public function test_the_readme_documents_the_cidr_limitation(): void
    {
        // v0.1.0 ships exact matching only; the limitation is documented so a
        // host does not assume a CIDR entry silently works.
        $this->assertMatchesRegularExpression(
            '/CIDR/u',
            $this->readme(),
            'The README must state that CIDR notation is not supported.',
        );
    }
}
