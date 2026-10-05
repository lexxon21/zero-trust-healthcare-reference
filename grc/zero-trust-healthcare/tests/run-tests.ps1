<#
.SYNOPSIS
  Runs validate-crosswalk.ps1 against the fixtures in tests\fixtures and checks every exit code and
  finding.

.DESCRIPTION
  Reference work. Fictional scenario built for a public portfolio. Not deployed in, derived from,
  or describing any employer environment. Not professional advice.

  fixtures\good.yaml and fixtures\good.md are a minimal known-good crosswalk: all 65 HIPAA rows,
  with a small architecture set (fixtures\architecture), a grc document, and a detection file. Each
  bad-* fixture is one base file (good.yaml, good.md, or ..\crosswalk.schema.json) with exactly one
  change, defined in the case table below. Before a case runs, this script confirms that the fixture
  on disk still equals its base plus that change, so a fixture cannot drift into testing something
  else. bad-root-list.yaml, engine-bad.yaml, and engine.schema.json stand alone.

  Each case runs the validator in its own Windows PowerShell 5.1 process, the way it is run by hand,
  with -Path, -Schema, and -Markdown pointing at fixtures. A case passes only when the exit code and
  the complete list of findings (severity, check, and message, in order) match the case.

  The literal em dash case is written from the case table at run time, run, and deleted, so no file
  in this folder holds an em dash. A final check confirms that.

.PARAMETER Rebuild
  Rewrite every bad-* fixture from its base and the case table, then run the tests. Use it after
  changing good.yaml, good.md, or crosswalk.schema.json on purpose.

.PARAMETER Case
  Run only the cases whose names match this wildcard pattern.

.PARAMETER Detail
  Print the findings of every case, not only of failing ones.

.PARAMETER Validator
  The validator to test. Default: ..\validate-crosswalk.ps1. Point it at a changed copy to see which
  cases a change breaks.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\run-tests.ps1

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\run-tests.ps1 -Case 'bad-md-*' -Detail

.NOTES
  Exit codes: 0 every case passed; 1 one or more cases failed; 2 the runner could not run.
  Written 2026-10-04 for Windows PowerShell 5.1 with no modules.
#>
[CmdletBinding()]
param(
  [switch]$Rebuild,
  [string]$Case = '*',
  [switch]$Detail,
  [string]$Validator
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:PsExe = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\powershell.exe')
$testsDir = $PSScriptRoot
if (-not $testsDir) { $testsDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$fx = [IO.Path]::Combine($testsDir, 'fixtures')
if ($Validator) { $validator = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Validator) }
else { $validator = [IO.Path]::GetFullPath([IO.Path]::Combine($testsDir, '..\validate-crosswalk.ps1')) }
$realSchema = [IO.Path]::GetFullPath([IO.Path]::Combine($testsDir, '..\crosswalk.schema.json'))
$emDash = [string][char]0x2014
$enDash = [string][char]0x2013
# The six-character YAML escapes for those dashes, assembled so that this file holds neither the
# characters nor the escapes as literal text.
$escEm = [string][char]92 + 'u' + '2014'
$escEn = [string][char]92 + 'u' + '2013'

$skipWarn = 'WARN [schema] content, file, and markdown checks were skipped because the structure is invalid; fix the schema findings first'

# ------------------------------------------------------------------ cases
# Role says which validator input the fixture replaces (Path, Markdown, or Schema); the other inputs
# stay good.yaml, good.md, and the real crosswalk.schema.json. A change is: find the first Find text
# after the unique After anchor (or the unique Find text when there is no anchor) and put Replace in
# its place; ThroughEnd replaces from Find to the end of the file. Yaml and Schema name a standalone
# fixture instead, and Args adds validator switches. Expected findings may use <<fixtures>> (the
# fixtures folder) and <<yamlline:TEXT>> or <<mdline:TEXT>> (the first line of the case's YAML or
# Markdown file that contains TEXT). A stopped run (exit 2) reports as one line: ERROR <message>.
$cases = @(
  @{ Name = 'good'; Purpose = 'known-good minimal crosswalk: no findings of any severity'; Exit = 0; Expect = @() },
  @{ Name = 'good-text-report'; Purpose = 'known-good crosswalk, human-readable report and statistics'; Mode = 'Text'; Exit = 0; Expect = @(
      'validate-crosswalk: <<fixtures>>\good.yaml',
      '',
      'Rows: 65 (applicable 60, indirect 1, not applicable 4)',
      'Coverage: designed 1, partial 2, procedural 56, out of scope 2, not applicable 4',
      'CSF 2.0 links: 62 (equivalent 1, partial 57, related 4); distinct subcategories 5',
      'PCI DSS v4.0.1 links: 2 on 2 CDE-scoped rows; detections linked: 1',
      'Result: PASS (0 warning(s))') },
  @{ Name = 'good-skip-switches'; Purpose = '-SkipFileChecks and -SkipMarkdown skip their stages with a warning each'
     Args = @('-SkipFileChecks', '-SkipMarkdown'); Exit = 0; Expect = @(
      'WARN [files] cross-file checks skipped (-SkipFileChecks)',
      'WARN [markdown] crosswalk.md agreement check skipped (-SkipMarkdown)') },
  @{ Name = 'missing-yaml-file'; Purpose = 'a crosswalk file that does not exist: the validator cannot run'
     Yaml = 'no-such-file.yaml'; Exit = 2; Expect = @('ERROR STOP: crosswalk file not found: <<fixtures>>\no-such-file.yaml') },

  # schema stage
  @{ Name = 'bad-enum-relationship'; Purpose = 'enum: CSF relationship outside equivalent, partial, related'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-01"'; Find = 'relationship: "partial"'; Replace = 'relationship: "partly"'
     Exit = 1; Expect = @('FAIL [schema] $.mappings[0].csf_targets[0].relationship: ''partly'' is not an allowed value', $skipWarn) },
  @{ Name = 'bad-enum-csf-id'; Purpose = 'enum: ID.AM-06, withdrawn in CSF 2.0, as a CSF target'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-01"'; Find = 'id: "GV.PO-01"'; Replace = 'id: "ID.AM-06"'
     Exit = 1; Expect = @('FAIL [schema] $.mappings[0].csf_targets[0].id: ''ID.AM-06'' is not an allowed value', $skipWarn) },
  @{ Name = 'bad-missing-key'; Purpose = 'required: a nested citation without its locator'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-63"'; Find = ('        locator: "45 CFR 164.316(b)(2)(i)"' + "`n"); Replace = ''
     Exit = 1; Expect = @('FAIL [schema] $.mappings[62].source.citation: missing required key ''locator''', $skipWarn) },
  @{ Name = 'bad-type'; Purpose = 'type: cde_scope as a string instead of a boolean'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-03"'; Find = 'cde_scope: false'; Replace = 'cde_scope: "false"'
     Exit = 1; Expect = @('FAIL [schema] $.mappings[2].cde_scope: expected boolean, found string', $skipWarn) },
  @{ Name = 'bad-pattern'; Purpose = 'pattern: mapping id XW-3'
     Role = 'Path'; Base = 'good.yaml'; Find = '  - id: "XW-03"'; Replace = '  - id: "XW-3"'
     Exit = 1; Expect = @('FAIL [schema] $.mappings[2].id: ''XW-3'' does not match ^XW-[0-9]{2}$', $skipWarn) },
  @{ Name = 'bad-pattern-newline'; Purpose = 'pattern: ECMA-262 $ rejects a trailing newline that .NET $ accepts'
     Role = 'Path'; Base = 'good.yaml'; Find = '  - id: "XW-04"'; Replace = '  - id: "XW-04\n"'
     Exit = 1; Expect = @('FAIL [schema] $.mappings[3].id: ''XW-04\n'' does not match ^XW-[0-9]{2}$', $skipWarn) },
  @{ Name = 'bad-nested'; Purpose = 'pattern deep in arrays and objects: a PCI target citation source'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-02"'; Find = 'source: "SRC-PCI-DSS-401"'; Replace = 'source: "src-pci-dss-401"'
     Exit = 1; Expect = @('FAIL [schema] $.mappings[1].pci_targets[0].citation.source: ''src-pci-dss-401'' does not match ^SRC-[A-Z0-9]+(-[A-Z0-9]+)*$', $skipWarn) },
  @{ Name = 'bad-unique'; Purpose = 'uniqueItems: the same component twice'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-01"'; Find = 'components: ["PE-FIXTURE", "PEP-FIXTURE"]'; Replace = 'components: ["PE-FIXTURE", "PE-FIXTURE"]'
     Exit = 1; Expect = @('FAIL [schema] $.mappings[0].architecture.components[1]: duplicate item ''PE-FIXTURE'' (same as item 0)', $skipWarn) },
  @{ Name = 'bad-hitrust-flag'; Purpose = 'HITRUST: identifiers_included set to true'
     Role = 'Path'; Base = 'good.yaml'; Find = 'identifiers_included: false'; Replace = 'identifiers_included: true'
     Exit = 1; Expect = @('FAIL [schema] $.metadata.hitrust.identifiers_included: must equal false, found true', $skipWarn) },
  @{ Name = 'bad-hitrust-target'; Purpose = 'HITRUST: a hitrust_targets key added to a mapping row (placeholder value, not a HITRUST identifier)'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-01"'; Find = '    notes: ""'; Replace = ('    notes: ""' + "`n" + '    hitrust_targets: ["PLACEHOLDER"]')
     Exit = 1; Expect = @('FAIL [schema] $.mappings[0]: unexpected key ''hitrust_targets''', $skipWarn) },
  @{ Name = 'bad-root-list'; Purpose = 'a one-item top-level list stays an array (not unrolled into an object)'
     Yaml = 'bad-root-list.yaml'
     Exit = 1; Expect = @('FAIL [schema] $: expected object, found array', $skipWarn) },
  @{ Name = 'engine-bad'; Purpose = 'schema engine: type arrays, deep const/enum/uniqueItems, one-item enum and required, $ref, length in code points'
     Yaml = 'engine-bad.yaml'; Schema = 'engine.schema.json'
     Exit = 1; Expect = @(
      'FAIL [schema] $.nullable_bad: expected string or null, found boolean',
      'FAIL [schema] $.objects_dup[1]: duplicate item {"b":"2","a":"1"} (same as item 0)',
      'FAIL [schema] $.const_bad: must equal {"a":"1","b":["2","3"]}, found {"a":"1","b":["3","2"]}',
      'FAIL [schema] $.enum_bad: ["q","p"] is not an allowed value',
      'FAIL [schema] $.single_bad: missing required key ''only''',
      'FAIL [schema] $.maxlen_bad: longer than 1 characters',
      $skipWarn) },
  @{ Name = 'bad-schema-keyword'; Purpose = 'a schema keyword the validator does not implement stops the run'
     Role = 'Schema'; Base = '..\..\crosswalk.schema.json'
     Find = '"date": { "type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" },'
     Replace = '"date": { "type": "string", "format": "date", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" },'
     Exit = 2; Expect = @('ERROR STOP: schema uses the unsupported keyword ''format'' at #/definitions/date') },
  @{ Name = 'bad-schema-type-name'; Purpose = 'a misspelled type name in the schema stops the run instead of failing every value'
     Role = 'Schema'; Base = '..\..\crosswalk.schema.json'
     Find = '"text": { "type": "string", "minLength": 1 },'; Replace = '"text": { "type": "strnig", "minLength": 1 },'
     Exit = 2; Expect = @('ERROR STOP: #/definitions/text/type: ''strnig'' is not a JSON Schema type name') },
  @{ Name = 'bad-schema-ref-case'; Purpose = 'a $ref that matches a definition only when case is ignored does not resolve'
     Role = 'Schema'; Base = '..\..\crosswalk.schema.json'
     Find = '"coverage_note": { "$ref": "#/definitions/text" },'; Replace = '"coverage_note": { "$ref": "#/definitions/Text" },'
     Exit = 2; Expect = @('ERROR STOP: schema reference ''#/definitions/Text'' does not resolve') },

  # text and parse stages
  @{ Name = 'bad-yaml-syntax'; Purpose = 'YAML subset: an unquoted string value'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-05"'; Find = 'coverage_note: "Fixture."'; Replace = 'coverage_note: Fixture.'
     Exit = 1; Expect = @('FAIL [yaml] YAML line <<yamlline:coverage_note: Fixture.>>: unquoted value ''Fixture.''; quote strings with double quotes (only true, false, null, [] and {} may be bare)') },
  @{ Name = 'bad-em-dash-literal'; Purpose = 'em dash character in the file (written at run time, then deleted)'
     Role = 'Path'; Base = 'good.yaml'; Generated = $true; After = 'id: "XW-06"'; Find = 'notes: ""'; Replace = ('notes: "Fixture ' + $emDash + ' note."')
     Exit = 1; Expect = @(
      'FAIL [text] line <<yamlline:notes: "Fixture>>: em dash; use a comma, colon, or parentheses',
      'WARN [text] line <<yamlline:notes: "Fixture>>: non-ASCII character; this file is kept ASCII-only') },
  @{ Name = 'bad-em-dash-escape'; Purpose = ('em dash written as the ' + $escEm + ' escape inside a quoted string')
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-06"'; Find = 'notes: ""'; Replace = ('notes: "Fixture ' + $escEm + ' note."')
     Exit = 1; Expect = @(('FAIL [text] line <<yamlline:notes: "Fixture>>: em dash written as the escape ' + $escEm + '; use a comma, colon, or parentheses')) },
  @{ Name = 'warn-en-dash-escape'; Purpose = 'en dash escape is a warning only, so the exit code stays 0'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-06"'; Find = 'notes: ""'; Replace = ('notes: "Pages 1 ' + $escEn + ' 2."')
     Exit = 0; Expect = @(('WARN [text] line <<yamlline:notes: "Pages>>: en dash written as the escape ' + $escEn + '; write ranges as ''X to Y''')) },

  # content stage
  @{ Name = 'bad-content-pci-scope'; Purpose = 'PCI DSS targets on a row that is not CDE-scoped'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-02"'; Find = 'cde_scope: true'; Replace = 'cde_scope: false'
     Exit = 1; Expect = @('FAIL [content] mappings[1] XW-02 (164.308(a)(1)(ii)(A)): PCI DSS targets are allowed only on rows with cde_scope true (Z-CDE segment only)') },
  @{ Name = 'bad-content-missing-row'; Purpose = 'a HIPAA implementation specification with no row'
     Role = 'Path'; Base = 'good.yaml'; Find = '  - id: "XW-65"'; ThroughEnd = $true; Replace = ''
     Exit = 1; Expect = @(
      'FAIL [content] missing a row for 45 CFR 164.316(b)(2)(iii) (Updates)',
      'FAIL [markdown] good.md line <<mdline:[164.316(b)(2)(iii)]>>: 164.316(b)(2)(iii) has no row in bad-content-missing-row.yaml') },
  @{ Name = 'bad-locator'; Purpose = 'a citation locator that names a different requirement (11.2.3 for 1.2.3)'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-02"'; Find = 'locator: "Requirement 1.2.3"'; Replace = 'locator: "Requirement 11.2.3"'
     Exit = 1; Expect = @('FAIL [content] mappings[1] XW-02 (164.308(a)(1)(ii)(A)) PCI 1.2.3: citation locator ''Requirement 11.2.3'' does not name 1.2.3') },

  # file stage
  @{ Name = 'bad-id-ref'; Purpose = 'a component ID that is not in the architecture glossary'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-01"'; Find = 'components: ["PE-FIXTURE", "PEP-FIXTURE"]'; Replace = 'components: ["PE-FIXTURE", "PEP-MISSING"]'
     Exit = 1; Expect = @(
      'FAIL [files] XW-01: PEP-MISSING is not defined in the component glossary (02, Component glossary)',
      'INFO [files] 1 glossary component(s) are not referenced by any row: PEP-FIXTURE') },
  @{ Name = 'bad-section-ref'; Purpose = 'a section that exists only inside a code fence, so not as a heading'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-01"'; Find = 'section: "1"'; Replace = 'section: "9"'
     Exit = 1; Expect = @('FAIL [files] XW-01: no heading for section ''9'' in 02-reference-architecture.md') },
  @{ Name = 'bad-file-ref'; Purpose = 'an artifact file that does not exist'
     Role = 'Path'; Base = 'good.yaml'; After = 'id: "XW-01"'; Find = 'file: "adr/ADR-001-fixture.md"'; Replace = 'file: "adr/ADR-009-missing.md"'
     Exit = 1; Expect = @('FAIL [files] XW-01: file not found: <<fixtures>>\architecture\adr\ADR-009-missing.md') },

  # markdown stage
  @{ Name = 'bad-md-csf'; Purpose = 'crosswalk.md: a CSF relationship that disagrees with the YAML'
     Role = 'Markdown'; Base = 'good.md'; Find = '| GV.PO-01 (partial); PR.AA-05 (related) |'; Replace = '| GV.PO-01 (equivalent); PR.AA-05 (related) |'
     Exit = 1; Expect = @('FAIL [markdown] bad-md-csf.md line <<mdline:PR.AA-05>> (164.308(a)(1)(i)): CSF targets [GV.PO-01 equivalent, PR.AA-05 related] differ from good.yaml [GV.PO-01 partial, PR.AA-05 related]') },
  @{ Name = 'bad-md-coverage'; Purpose = 'crosswalk.md: a coverage value that disagrees with the YAML'
     Role = 'Markdown'; Base = 'good.md'; After = '[164.308(a)(1)(ii)(A)]'; Find = '| partial |'; Replace = '| designed |'
     Exit = 1; Expect = @('FAIL [markdown] bad-md-coverage.md line <<mdline:[164.308(a)(1)(ii)(A)]>> (164.308(a)(1)(ii)(A)): coverage ''designed'' differs from good.yaml ''partial''') },
  @{ Name = 'bad-md-pci'; Purpose = 'crosswalk.md: a PCI DSS target missing from the table'
     Role = 'Markdown'; Base = 'good.md'; After = '[164.308(a)(6)(i)]'; Find = '| 12.10.1 |'; Replace = '| none |'
     Exit = 1; Expect = @('FAIL [markdown] bad-md-pci.md line <<mdline:[164.308(a)(6)(i)]>> (164.308(a)(6)(i)): PCI DSS targets [] differ from good.yaml [12.10.1]') },
  @{ Name = 'bad-md-case'; Purpose = 'crosswalk.md: a HIPAA citation that differs from the YAML only in letter case'
     Role = 'Markdown'; Base = 'good.md'; Find = '[164.308(a)(1)(ii)(A)]'; Replace = '[164.308(a)(1)(ii)(a)]'
     Exit = 1; Expect = @(
      'FAIL [markdown] bad-md-case.md line <<mdline:[164.308(a)(1)(ii)(a)]>>: 164.308(a)(1)(ii)(a) has no row in good.yaml',
      'FAIL [markdown] bad-md-case.md has no row for 164.308(a)(1)(ii)(A)') }
)

# ------------------------------------------------------------------ helpers
function Read-Text([string]$File) { return [IO.File]::ReadAllText($File, [Text.Encoding]::UTF8) }

function Write-Text([string]$File, [string]$Text) { [IO.File]::WriteAllText($File, $Text, $script:Utf8NoBom) }

function Get-Opt($Table, [string]$Key) {
  if ($Table.ContainsKey($Key)) { return $Table[$Key] }
  return $null
}

# Applies a case's single change to its base text.
function Get-Mutated([string]$Text, $C) {
  $start = 0
  $after = Get-Opt $C 'After'
  if ($null -ne $after) {
    $start = $Text.IndexOf($after, [StringComparison]::Ordinal)
    if ($start -lt 0) { throw ("anchor not found: {0}" -f $after) }
    if ($Text.IndexOf($after, $start + 1, [StringComparison]::Ordinal) -ge 0) { throw ("anchor is not unique: {0}" -f $after) }
  }
  $find = [string]$C.Find
  $idx = $Text.IndexOf($find, $start, [StringComparison]::Ordinal)
  if ($idx -lt 0) { throw ("text to change not found: {0}" -f $find) }
  if ($null -eq $after -and $Text.IndexOf($find, $idx + 1, [StringComparison]::Ordinal) -ge 0) { throw ("text to change is not unique: {0}" -f $find) }
  $end = $idx + $find.Length
  if ($true -eq (Get-Opt $C 'ThroughEnd')) { $end = $Text.Length }
  return $Text.Substring(0, $idx) + [string]$C.Replace + $Text.Substring($end)
}

function Get-LineNumber([string]$File, [string]$Needle) {
  $lines = [regex]::Split((Read-Text $File), '\r\n|\n|\r')
  for ($i = 0; $i -lt $lines.Length; $i++) { if ($lines[$i].IndexOf($Needle, [StringComparison]::Ordinal) -ge 0) { return ($i + 1) } }
  throw ("no line in {0} contains: {1}" -f $File, $Needle)
}

function Expand-Expected([string]$Text, [string]$Yaml, [string]$Md) {
  $t = $Text.Replace('<<fixtures>>', $fx)
  while ($true) {
    $m = [regex]::Match($t, '<<(yaml|md)line:(.*?)>>')
    if (-not $m.Success) { break }
    $file = $Yaml
    if ($m.Groups[1].Value -ceq 'md') { $file = $Md }
    $t = $t.Substring(0, $m.Index) + [string](Get-LineNumber $file $m.Groups[2].Value) + $t.Substring($m.Index + $m.Length)
  }
  return $t
}

function ConvertTo-ProcessArg([string]$Arg) {
  if ($Arg.Length -gt 0 -and -not [regex]::IsMatch($Arg, '[\s"]')) { return $Arg }
  return '"' + $Arg.Replace('"', '\"') + '"'
}

# Runs the validator in its own process and returns exit code, standard output, and standard error.
function Invoke-Validator([string[]]$ArgList) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:PsExe
  $psi.Arguments = [string]::Join(' ', @(foreach ($a in $ArgList) { ConvertTo-ProcessArg $a }))
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $outTask = $p.StandardOutput.ReadToEndAsync()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  return @{ Exit = $p.ExitCode; Out = $outTask.Result; Err = $err }
}

# ------------------------------------------------------------------ main
$exitCode = 2
$generated = New-Object 'System.Collections.Generic.List[string]'
try {
  foreach ($f in @($validator, $realSchema, $script:PsExe, [IO.Path]::Combine($fx, 'good.yaml'), [IO.Path]::Combine($fx, 'good.md'))) {
    if (-not [IO.File]::Exists($f)) { throw ("required file not found: {0}" -f $f) }
  }
  Write-Output ('validate-crosswalk fixture tests')
  Write-Output ('validator: ' + $validator)
  Write-Output ('fixtures:  ' + $fx)
  Write-Output ''

  $passed = 0
  $failed = 0
  $selected = @($cases | Where-Object { $_.Name -like $Case })
  if ($selected.Count -eq 0) { throw ("no case matches '{0}'" -f $Case) }

  foreach ($c in $selected) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $role = Get-Opt $c 'Role'
    $yaml = [IO.Path]::Combine($fx, 'good.yaml')
    $md = [IO.Path]::Combine($fx, 'good.md')
    $schema = $realSchema
    if ($null -ne (Get-Opt $c 'Yaml')) { $yaml = [IO.Path]::Combine($fx, $c.Yaml) }
    if ($null -ne (Get-Opt $c 'Schema')) { $schema = [IO.Path]::Combine($fx, $c.Schema) }

    # Fixture file for a one-change case: built at run time, rebuilt on request, or checked for drift.
    $base = Get-Opt $c 'Base'
    if ($null -ne $base) {
      $ext = [IO.Path]::GetExtension($c.Base)
      if ($c.Base.EndsWith('.schema.json', [StringComparison]::Ordinal)) { $ext = '.schema.json' }
      $fixtureName = $c.Name + $ext
      if ($true -eq (Get-Opt $c 'Generated')) { $fixtureName = 'tmp-' + $PID + '-' + $c.Name + $ext }
      $fixture = [IO.Path]::Combine($fx, $fixtureName)
      $wanted = Get-Mutated (Read-Text ([IO.Path]::GetFullPath([IO.Path]::Combine($fx, $c.Base)))) $c
      if ($true -eq (Get-Opt $c 'Generated')) {
        Write-Text $fixture $wanted
        $generated.Add($fixture)
      } elseif ($Rebuild) {
        Write-Text $fixture $wanted
      } elseif (-not [IO.File]::Exists($fixture)) {
        $problems.Add(("fixture missing: {0} (run with -Rebuild)" -f $fixtureName))
      } elseif ((Read-Text $fixture) -cne $wanted) {
        $problems.Add(("fixture drift: {0} is no longer {1} with exactly the one change in its case (run with -Rebuild if the base changed on purpose)" -f $fixtureName, $c.Base))
      }
      if ($role -ceq 'Path') { $yaml = $fixture }
      elseif ($role -ceq 'Markdown') { $md = $fixture }
      elseif ($role -ceq 'Schema') { $schema = $fixture }
      else { throw ("case {0}: Role must be Path, Markdown, or Schema" -f $c.Name) }
    }

    $mode = Get-Opt $c 'Mode'
    $actual = New-Object 'System.Collections.Generic.List[string]'
    $actualExit = $null
    if ($problems.Count -eq 0) {
      $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $validator, '-Path', $yaml, '-Schema', $schema, '-Markdown', $md)
      $extra = Get-Opt $c 'Args'
      if ($null -ne $extra) { $argList += $extra }
      if ($mode -cne 'Text') { $argList += '-Json' }
      $r = Invoke-Validator $argList
      $actualExit = $r.Exit
      if ($mode -ceq 'Text') {
        $lines = [regex]::Split($r.Out, '\r\n|\n|\r')
        $n = $lines.Length
        if ($n -gt 0 -and $lines[$n - 1].Length -eq 0) { $n-- }
        for ($i = 0; $i -lt $n; $i++) { $actual.Add($lines[$i]) }
      } else {
        $obj = $null
        try { $obj = $r.Out | ConvertFrom-Json } catch { $problems.Add(('output is not JSON: ' + $r.Out.Trim() + ' ' + $r.Err.Trim())) }
        if ($null -ne $obj) {
          if ($null -ne $obj.PSObject.Properties['error']) { $actual.Add('ERROR ' + $obj.error) }
          foreach ($f in $obj.findings) { $actual.Add(('{0} [{1}] {2}' -f $f.severity, $f.check, $f.message)) }
        }
      }
    }

    $expected = @(foreach ($e in $c.Expect) { Expand-Expected $e $yaml $md })
    # A run-time fixture is needed only for its own case; delete it now (the finally block below
    # is the backstop if the run stops early).
    if ($true -eq (Get-Opt $c 'Generated')) {
      foreach ($g in $generated) { if ([IO.File]::Exists($g)) { [IO.File]::Delete($g) } }
      $generated.Clear()
    }
    if ($problems.Count -eq 0) {
      if ($actualExit -ne $c.Exit) { $problems.Add(("exit code {0}, expected {1}" -f $actualExit, $c.Exit)) }
      $max = [Math]::Max($expected.Count, $actual.Count)
      for ($i = 0; $i -lt $max; $i++) {
        $e = $null; $a = $null
        if ($i -lt $expected.Count) { $e = $expected[$i] }
        if ($i -lt $actual.Count) { $a = $actual[$i] }
        if ($null -eq $a) { $problems.Add(('missing finding: ' + $e)) }
        elseif ($null -eq $e) { $problems.Add(('unexpected finding: ' + $a)) }
        elseif ($e -cne $a) { $problems.Add(('finding {0} differs' -f ($i + 1))); $problems.Add(('  expected: ' + $e)); $problems.Add(('  actual:   ' + $a)) }
      }
    }

    $label = 'findings'
    if ($mode -ceq 'Text') { $label = 'report lines' }
    if ($problems.Count -eq 0) {
      $passed++
      Write-Output ('PASS  {0,-24} exit {1} (expected {2}); {3} {4} as expected; {5}' -f $c.Name, $actualExit, $c.Exit, $actual.Count, $label, $c.Purpose)
      if ($Detail) { foreach ($a in $actual) { Write-Output ('        ' + $a) } }
    } else {
      $failed++
      Write-Output ('FAIL  {0,-24} {1}' -f $c.Name, $c.Purpose)
      foreach ($p in $problems) { Write-Output ('        ' + $p) }
      foreach ($a in $actual) { Write-Output ('        actual: ' + $a) }
    }
  }

  # Clean up run-time fixtures, then confirm no file under tests holds an em or en dash.
  foreach ($g in $generated) { if ([IO.File]::Exists($g)) { [IO.File]::Delete($g) } }
  $generated.Clear()
  $dashFiles = @(foreach ($file in [IO.Directory]::GetFiles($testsDir, '*', [IO.SearchOption]::AllDirectories)) {
      $text = Read-Text $file
      if ($text.Contains($emDash) -or $text.Contains($enDash)) { $file }
    })
  if ($dashFiles.Count -eq 0) {
    $passed++
    Write-Output ('PASS  {0,-24} no file under tests holds an em or en dash after the run' -f 'no-dash-files')
  } else {
    $failed++
    Write-Output ('FAIL  {0,-24} files holding an em or en dash: {1}' -f 'no-dash-files', ($dashFiles -join ', '))
  }

  Write-Output ''
  Write-Output ('Result: {0} passed, {1} failed' -f $passed, $failed)
  if ($failed -eq 0) { $exitCode = 0 } else { $exitCode = 1 }
} catch {
  Write-Output ('run-tests could not run: ' + $_.Exception.Message)
  $exitCode = 2
} finally {
  foreach ($g in $generated) { if ([IO.File]::Exists($g)) { [IO.File]::Delete($g) } }
}
exit $exitCode
