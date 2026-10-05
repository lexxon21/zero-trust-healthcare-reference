<#
.SYNOPSIS
  Validates crosswalk.yaml, the Contoso Regional Health (fictional) HIPAA Security Rule crosswalk.

.DESCRIPTION
  Reference work. Fictional scenario built for a public portfolio. Not deployed in, derived from,
  or describing any employer environment. Not professional advice.

  Runs on Windows PowerShell 5.1 with no modules. It reads a strict YAML subset (the format rules
  are in the header of crosswalk.yaml) and checks, in order:

    1. text       Em dashes (FAIL); en dashes, non-ASCII characters, VERIFY markers (WARN). An em
                  or en dash written as a \u escape inside a quoted string is reported the same way
                  while the file is parsed.
    2. yaml       The file parses under the subset rules (FAIL with a line number if not).
    3. schema     Structure against crosswalk.schema.json, using the JSON Schema draft-07 keywords
                  this script implements, with ECMA-262 pattern semantics. Any other keyword, or a
                  malformed keyword value, in the schema stops the run (exit 2).
    4. content    Every standard and implementation specification in 45 CFR 164.308, 164.310,
                  164.312, 164.314, and 164.316 appears exactly once with the right kind, title, and
                  Required/Addressable designation; applicability and coverage agree; CSF and PCI
                  identifiers come from the catalogs in metadata; PCI DSS targets appear only on rows
                  scoped to the cardholder data environment (Z-CDE); every citation resolves to a
                  source; citation locators name the identifier they cite.
    5. files      Component, zone, Conditional Access policy, flow, and residual-risk IDs exist in
                  the architecture documents; every referenced file exists; every referenced section
                  exists as a heading. Skipped with -SkipFileChecks.
    6. markdown   Every crosswalk table row in crosswalk.md agrees with the YAML (CSF targets and
                  relationships, coverage, PCI DSS targets), and every YAML row appears once.
                  Skipped with -SkipMarkdown.

  Structure, content, file, and markdown checks run only when the earlier stages pass, so fix
  findings in the order reported.

.PARAMETER Path
  The crosswalk YAML. Default: crosswalk.yaml next to this script.

.PARAMETER Schema
  The JSON schema. Default: crosswalk.schema.json next to this script.

.PARAMETER Markdown
  The human-readable crosswalk. Default: crosswalk.md next to the YAML file.

.PARAMETER SkipFileChecks
  Skip checks against the architecture folder, for example in a repository layout where the
  paths in metadata.paths have not been updated yet.

.PARAMETER SkipMarkdown
  Skip the crosswalk.md agreement check.

.PARAMETER Json
  Print one single-line ASCII JSON object instead of the human-readable report.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\validate-crosswalk.ps1

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\validate-crosswalk.ps1 -Json

.NOTES
  Exit codes: 0 no FAIL findings (WARN findings may exist); 1 one or more FAIL findings;
  2 the validator could not run (missing file, invalid schema JSON, unsupported schema keyword,
  or an internal error).
  Tests: tests\run-tests.ps1 runs this script against the fixtures in tests\fixtures and checks
  every exit code and finding.
#>
[CmdletBinding()]
param(
  [string]$Path,
  [string]$Schema,
  [string]$Markdown,
  [switch]$SkipFileChecks,
  [switch]$SkipMarkdown,
  [switch]$Json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ state and constants
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:YL = $null
$script:SchemaRoot = $null
$script:HeadingCache = @{}
$script:QuoteChar = [char]34
$script:BackslashChar = [char]92

$script:AllowedKeywords = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::Ordinal)
foreach ($kw in @('$schema', '$id', '$comment', 'title', 'description', 'default', 'examples', 'definitions',
    '$ref', 'type', 'properties', 'required', 'additionalProperties', 'items', 'minItems', 'maxItems',
    'uniqueItems', 'enum', 'const', 'pattern', 'minLength', 'maxLength')) {
  [void]$script:AllowedKeywords.Add($kw)
}

$script:CdeComponents = @('RES-POI', 'PEP-CDE-BOUNDARY', 'EXT-P2PE', 'EXT-PSP')

$script:MdHipaaHeader = 'HIPAA'
$script:MdCsfHeader = 'CSF 2.0 targets'
$script:MdCoverageHeader = 'Coverage'
$script:MdPciHeader = 'PCI DSS v4.0.1 (CDE only)'

# Every standard and implementation specification in 45 CFR 164.308 to 164.316, as in force.
# Format: id|kind|designation|title. Titles and R/A labels follow the regulation text (eCFR, current
# through 2026-09-30) and Appendix A to Subpart C. Standards are mandatory (45 CFR 164.306(c)).
$script:ExpectedHipaaText = @'
164.308(a)(1)(i)|standard|standard|Security management process
164.308(a)(1)(ii)(A)|implementation-specification|required|Risk analysis
164.308(a)(1)(ii)(B)|implementation-specification|required|Risk management
164.308(a)(1)(ii)(C)|implementation-specification|required|Sanction policy
164.308(a)(1)(ii)(D)|implementation-specification|required|Information system activity review
164.308(a)(2)|standard|standard|Assigned security responsibility
164.308(a)(3)(i)|standard|standard|Workforce security
164.308(a)(3)(ii)(A)|implementation-specification|addressable|Authorization and/or supervision
164.308(a)(3)(ii)(B)|implementation-specification|addressable|Workforce clearance procedure
164.308(a)(3)(ii)(C)|implementation-specification|addressable|Termination procedures
164.308(a)(4)(i)|standard|standard|Information access management
164.308(a)(4)(ii)(A)|implementation-specification|required|Isolating health care clearinghouse functions
164.308(a)(4)(ii)(B)|implementation-specification|addressable|Access authorization
164.308(a)(4)(ii)(C)|implementation-specification|addressable|Access establishment and modification
164.308(a)(5)(i)|standard|standard|Security awareness and training
164.308(a)(5)(ii)(A)|implementation-specification|addressable|Security reminders
164.308(a)(5)(ii)(B)|implementation-specification|addressable|Protection from malicious software
164.308(a)(5)(ii)(C)|implementation-specification|addressable|Log-in monitoring
164.308(a)(5)(ii)(D)|implementation-specification|addressable|Password management
164.308(a)(6)(i)|standard|standard|Security incident procedures
164.308(a)(6)(ii)|implementation-specification|required|Response and reporting
164.308(a)(7)(i)|standard|standard|Contingency plan
164.308(a)(7)(ii)(A)|implementation-specification|required|Data backup plan
164.308(a)(7)(ii)(B)|implementation-specification|required|Disaster recovery plan
164.308(a)(7)(ii)(C)|implementation-specification|required|Emergency mode operation plan
164.308(a)(7)(ii)(D)|implementation-specification|addressable|Testing and revision procedures
164.308(a)(7)(ii)(E)|implementation-specification|addressable|Applications and data criticality analysis
164.308(a)(8)|standard|standard|Evaluation
164.308(b)(1)|standard|standard|Business associate contracts and other arrangements
164.308(b)(3)|implementation-specification|required|Written contract or other arrangement
164.310(a)(1)|standard|standard|Facility access controls
164.310(a)(2)(i)|implementation-specification|addressable|Contingency operations
164.310(a)(2)(ii)|implementation-specification|addressable|Facility security plan
164.310(a)(2)(iii)|implementation-specification|addressable|Access control and validation procedures
164.310(a)(2)(iv)|implementation-specification|addressable|Maintenance records
164.310(b)|standard|standard|Workstation use
164.310(c)|standard|standard|Workstation security
164.310(d)(1)|standard|standard|Device and media controls
164.310(d)(2)(i)|implementation-specification|required|Disposal
164.310(d)(2)(ii)|implementation-specification|required|Media re-use
164.310(d)(2)(iii)|implementation-specification|addressable|Accountability
164.310(d)(2)(iv)|implementation-specification|addressable|Data backup and storage
164.312(a)(1)|standard|standard|Access control
164.312(a)(2)(i)|implementation-specification|required|Unique user identification
164.312(a)(2)(ii)|implementation-specification|required|Emergency access procedure
164.312(a)(2)(iii)|implementation-specification|addressable|Automatic logoff
164.312(a)(2)(iv)|implementation-specification|addressable|Encryption and decryption
164.312(b)|standard|standard|Audit controls
164.312(c)(1)|standard|standard|Integrity
164.312(c)(2)|implementation-specification|addressable|Mechanism to authenticate electronic protected health information
164.312(d)|standard|standard|Person or entity authentication
164.312(e)(1)|standard|standard|Transmission security
164.312(e)(2)(i)|implementation-specification|addressable|Integrity controls
164.312(e)(2)(ii)|implementation-specification|addressable|Encryption
164.314(a)(1)|standard|standard|Business associate contracts or other arrangements
164.314(a)(2)(i)|implementation-specification|required|Business associate contracts
164.314(a)(2)(ii)|implementation-specification|required|Other arrangements
164.314(a)(2)(iii)|implementation-specification|required|Business associate contracts with subcontractors
164.314(b)(1)|standard|standard|Requirements for group health plans
164.314(b)(2)|implementation-specification|required|Implementation specifications
164.316(a)|standard|standard|Policies and procedures
164.316(b)(1)|standard|standard|Documentation
164.316(b)(2)(i)|implementation-specification|required|Time limit
164.316(b)(2)(ii)|implementation-specification|required|Availability
164.316(b)(2)(iii)|implementation-specification|required|Updates
'@

# ------------------------------------------------------------------ general helpers
function Add-Finding([string]$Severity, [string]$Check, [string]$Message) {
  $script:Findings.Add([pscustomobject]@{ severity = $Severity; check = $Check; message = $Message })
}

function Stop-Run([string]$Message) {
  throw (New-Object System.InvalidOperationException -ArgumentList ('STOP: ' + $Message))
}

# Shortens a value for a message and shows control characters as escapes, so that one finding
# always stays on one line of the report.
function Get-Short([string]$Text, [int]$Max) {
  if ($null -eq $Text) { return '' }
  $t = $Text
  if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
  if (-not [regex]::IsMatch($t, '[\x00-\x1F\x7F]')) { return $t }
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $t.ToCharArray()) {
    $c = [int]$ch
    if ($c -eq 10) { [void]$sb.Append('\n') }
    elseif ($c -eq 13) { [void]$sb.Append('\r') }
    elseif ($c -eq 9) { [void]$sb.Append('\t') }
    elseif ($c -lt 32 -or $c -eq 127) { [void]$sb.Append('\u' + $c.ToString('x4')) }
    else { [void]$sb.Append($ch) }
  }
  return $sb.ToString()
}

function Resolve-FullPath([string]$PathText) {
  $p = $PathText.Trim().Trim($script:QuoteChar).Trim()
  if ($p.Length -eq 0) { Stop-Run 'an empty path was given' }
  $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)
  return [IO.Path]::GetFullPath($full)
}

function Get-FileLines([string]$File) {
  $text = [IO.File]::ReadAllText($File, [Text.Encoding]::UTF8)
  return ,([regex]::Split($text, '\r\n|\n|\r'))
}

function New-StringSet {
  return ,(New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::Ordinal))
}

function Get-SortedJoin($Items) {
  $arr = @(foreach ($x in $Items) { [string]$x })
  [Array]::Sort($arr, [StringComparer]::Ordinal)
  return [string]::Join(', ', $arr)
}

function ConvertTo-JsonText([string]$Text) {
  if ($null -eq $Text) { return 'null' }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  foreach ($ch in $Text.ToCharArray()) {
    $c = [int]$ch
    if ($c -eq 34) { [void]$sb.Append('\"') }
    elseif ($c -eq 92) { [void]$sb.Append('\\') }
    elseif ($c -lt 32 -or $c -gt 126) { [void]$sb.Append('\u' + $c.ToString('x4')) }
    else { [void]$sb.Append($ch) }
  }
  [void]$sb.Append('"')
  return $sb.ToString()
}

# ------------------------------------------------------------------ 1. text hygiene
function Test-TextHygiene([string[]]$Lines) {
  $em = [string][char]0x2014
  $en = [string][char]0x2013
  for ($i = 0; $i -lt $Lines.Length; $i++) {
    $l = $Lines[$i]
    $n = $i + 1
    if ($l.IndexOf($em, [StringComparison]::Ordinal) -ge 0) { Add-Finding 'FAIL' 'text' ("line {0}: em dash; use a comma, colon, or parentheses" -f $n) }
    if ($l.IndexOf($en, [StringComparison]::Ordinal) -ge 0) { Add-Finding 'WARN' 'text' ("line {0}: en dash; write ranges as 'X to Y'" -f $n) }
    if ([regex]::IsMatch($l, '[^\x00-\x7F]')) { Add-Finding 'WARN' 'text' ("line {0}: non-ASCII character; this file is kept ASCII-only" -f $n) }
    if ([regex]::IsMatch($l, '\bVERIFY\b')) { Add-Finding 'WARN' 'text' ("line {0}: VERIFY marker; resolve it before publication" -f $n) }
  }
}

# ------------------------------------------------------------------ 2. YAML subset reader
function New-YamlError([int]$LineNo, [string]$Message) {
  return (New-Object System.FormatException -ArgumentList ("YAML line {0}: {1}" -f $LineNo, $Message))
}

function Read-YamlLines([string]$Text) {
  $raw = [regex]::Split($Text, '\r\n|\n|\r')
  $list = New-Object 'System.Collections.Generic.List[object]'
  $sawContent = $false
  for ($i = 0; $i -lt $raw.Length; $i++) {
    $line = $raw[$i]
    if ($i -eq 0 -and $line.Length -gt 0 -and [int]$line[0] -eq 0xFEFF) { $line = $line.Substring(1) }
    $line = $line.TrimEnd()
    if ($line.Length -eq 0) { continue }
    $lead = [regex]::Match($line, '^[ \t]*').Value
    $content = $line.Substring($lead.Length)
    if ($content.StartsWith('#', [StringComparison]::Ordinal)) { continue }
    if ($lead.IndexOf("`t") -ge 0) { throw (New-YamlError ($i + 1) 'tab characters are not allowed in indentation') }
    if ($content -ceq '---') {
      if ($sawContent) { throw (New-YamlError ($i + 1) 'only one YAML document is supported') }
      continue
    }
    $sawContent = $true
    $list.Add([pscustomobject]@{ No = $i + 1; Indent = $lead.Length; Text = $content })
  }
  return ,$list
}

function Test-IsSeqLine([string]$Text) {
  return ($Text -ceq '-' -or $Text.StartsWith('- ', [StringComparison]::Ordinal))
}

function Read-YamlQuoted([string]$S, [int]$Start, [int]$LineNo) {
  $sb = New-Object System.Text.StringBuilder
  $i = $Start + 1
  while ($i -lt $S.Length) {
    $ch = $S[$i]
    if ($ch -ceq $script:QuoteChar) {
      return @{ Value = $sb.ToString(); Next = $i + 1 }
    }
    if ($ch -ceq $script:BackslashChar) {
      if (($i + 1) -ge $S.Length) { break }
      $e = $S[$i + 1]
      if ($e -ceq $script:QuoteChar) { [void]$sb.Append($script:QuoteChar); $i += 2; continue }
      if ($e -ceq $script:BackslashChar) { [void]$sb.Append($script:BackslashChar); $i += 2; continue }
      if ($e -ceq [char]'/') { [void]$sb.Append([char]'/'); $i += 2; continue }
      if ($e -ceq [char]'n') { [void]$sb.Append([char]10); $i += 2; continue }
      if ($e -ceq [char]'t') { [void]$sb.Append([char]9); $i += 2; continue }
      if ($e -ceq [char]'r') { [void]$sb.Append([char]13); $i += 2; continue }
      if ($e -ceq [char]'u') {
        if (($i + 5) -ge $S.Length) { throw (New-YamlError $LineNo 'incomplete \u escape') }
        $hex = $S.Substring($i + 2, 4)
        if (-not [regex]::IsMatch($hex, '^[0-9A-Fa-f]{4}$')) { throw (New-YamlError $LineNo ("invalid \u escape '{0}'" -f $hex)) }
        $code = [Convert]::ToInt32($hex, 16)
        # An escape puts the character in the value without putting it in the file text, so the
        # text check in stage 1 cannot see it. Apply the same dash rules here.
        if ($code -eq 0x2014) { Add-Finding 'FAIL' 'text' ("line {0}: em dash written as the escape \u{1}; use a comma, colon, or parentheses" -f $LineNo, $hex) }
        elseif ($code -eq 0x2013) { Add-Finding 'WARN' 'text' ("line {0}: en dash written as the escape \u{1}; write ranges as 'X to Y'" -f $LineNo, $hex) }
        [void]$sb.Append([char]$code)
        $i += 6
        continue
      }
      throw (New-YamlError $LineNo ("unsupported escape sequence '\{0}'" -f $e))
    }
    [void]$sb.Append($ch)
    $i++
  }
  throw (New-YamlError $LineNo 'unterminated double-quoted string')
}

function Read-YamlFlowSeq([string]$T, [int]$LineNo) {
  $list = New-Object 'System.Collections.Generic.List[object]'
  if (-not $T.EndsWith(']', [StringComparison]::Ordinal)) { throw (New-YamlError $LineNo 'a flow list must close with ] on the same line') }
  $close = $T.Length - 1
  $i = 1
  while ($i -lt $close -and $T[$i] -ceq [char]' ') { $i++ }
  if ($i -eq $close) { return ,$list }
  while ($true) {
    while ($i -lt $close -and $T[$i] -ceq [char]' ') { $i++ }
    if ($i -ge $close -or -not ($T[$i] -ceq $script:QuoteChar)) { throw (New-YamlError $LineNo 'flow list items must be double-quoted strings') }
    $r = Read-YamlQuoted $T $i $LineNo
    if ($r.Next -gt $close) { throw (New-YamlError $LineNo 'a quoted item runs past the closing ]') }
    $list.Add($r.Value)
    $i = $r.Next
    while ($i -lt $close -and $T[$i] -ceq [char]' ') { $i++ }
    if ($i -eq $close) { break }
    if ($T[$i] -ceq [char]',') { $i++; continue }
    throw (New-YamlError $LineNo "expected ',' or ']' in a flow list")
  }
  return ,$list
}

function ConvertFrom-YamlScalar([string]$Text, [int]$LineNo) {
  $t = $Text.Trim()
  if ($t.Length -eq 0) { return $null }
  if ($t[0] -ceq $script:QuoteChar) {
    $r = Read-YamlQuoted $t 0 $LineNo
    $tail = $t.Substring($r.Next).Trim()
    if ($tail.Length -gt 0) { throw (New-YamlError $LineNo ("unexpected text after a quoted string: '{0}' (inline comments are not supported)" -f (Get-Short $tail 40))) }
    return $r.Value
  }
  if ($t[0] -ceq [char]'[') { return ,(Read-YamlFlowSeq $t $LineNo) }
  if ($t -ceq '{}') { return (New-Object System.Collections.Specialized.OrderedDictionary) }
  if ($t -ceq 'true') { return $true }
  if ($t -ceq 'false') { return $false }
  if ($t -ceq 'null' -or $t -ceq '~') { return $null }
  throw (New-YamlError $LineNo ("unquoted value '{0}'; quote strings with double quotes (only true, false, null, [] and {{}} may be bare)" -f (Get-Short $t 40)))
}

function Read-YamlNode([int]$Index, [int]$Indent) {
  $line = $script:YL[$Index]
  if (Test-IsSeqLine $line.Text) { return (Read-YamlSeq $Index $Indent) }
  return (Read-YamlMap $Index $Indent)
}

function Read-YamlMap([int]$Index, [int]$Indent) {
  $map = New-Object System.Collections.Specialized.OrderedDictionary
  $i = $Index
  $n = $script:YL.Count
  while ($i -lt $n) {
    $line = $script:YL[$i]
    if ($line.Indent -lt $Indent) { break }
    if ($line.Indent -gt $Indent) { throw (New-YamlError $line.No 'unexpected indentation') }
    if (Test-IsSeqLine $line.Text) { throw (New-YamlError $line.No 'a list item cannot appear here; indent list items under their key') }
    $m = [regex]::Match($line.Text, '^([A-Za-z_][A-Za-z0-9_]*):(?: (.*))?$')
    if (-not $m.Success) { throw (New-YamlError $line.No ("expected 'key: value', found '{0}'" -f (Get-Short $line.Text 40))) }
    $key = $m.Groups[1].Value
    if ($map.Contains($key)) { throw (New-YamlError $line.No ("duplicate key '{0}'" -f $key)) }
    $rest = ''
    if ($m.Groups[2].Success) { $rest = $m.Groups[2].Value.Trim() }
    if ($rest.Length -eq 0) {
      if (($i + 1) -lt $n -and $script:YL[$i + 1].Indent -gt $Indent) {
        $r = Read-YamlNode ($i + 1) $script:YL[$i + 1].Indent
        $map[$key] = $r.Value
        $i = $r.Next
      } else {
        $map[$key] = $null
        $i++
      }
    } else {
      $map[$key] = ConvertFrom-YamlScalar $rest $line.No
      $i++
    }
  }
  return @{ Value = $map; Next = $i }
}

function Read-YamlSeq([int]$Index, [int]$Indent) {
  $list = New-Object 'System.Collections.Generic.List[object]'
  $i = $Index
  $n = $script:YL.Count
  while ($i -lt $n) {
    $line = $script:YL[$i]
    if ($line.Indent -lt $Indent) { break }
    if ($line.Indent -gt $Indent) { throw (New-YamlError $line.No 'unexpected indentation inside a list') }
    if (-not (Test-IsSeqLine $line.Text)) { throw (New-YamlError $line.No "expected a list item starting with '- '") }
    if ($line.Text -ceq '-') {
      if (($i + 1) -lt $n -and $script:YL[$i + 1].Indent -gt $Indent) {
        $r = Read-YamlNode ($i + 1) $script:YL[$i + 1].Indent
        $list.Add($r.Value)
        $i = $r.Next
      } else {
        $list.Add($null)
        $i++
      }
      continue
    }
    $after = $line.Text.Substring(2)
    $content = $after.TrimStart(' ')
    $extra = $after.Length - $content.Length
    if ([regex]::IsMatch($content, '^[A-Za-z_][A-Za-z0-9_]*:( |$)')) {
      $line.Indent = $Indent + 2 + $extra
      $line.Text = $content
      $r = Read-YamlMap $i $line.Indent
      $list.Add($r.Value)
      $i = $r.Next
    } else {
      $list.Add((ConvertFrom-YamlScalar $content $line.No))
      $i++
    }
  }
  return @{ Value = $list; Next = $i }
}

function ConvertFrom-YamlSubset([string]$Text) {
  $script:YL = Read-YamlLines $Text
  if ($script:YL.Count -eq 0) { throw (New-YamlError 1 'the file has no content') }
  $first = $script:YL[0]
  if ($first.Indent -ne 0) { throw (New-YamlError $first.No 'the first line must not be indented') }
  $r = Read-YamlNode 0 0
  if ($r.Next -lt $script:YL.Count) {
    $bad = $script:YL[$r.Next]
    throw (New-YamlError $bad.No 'unexpected content; check the indentation')
  }
  # The unary comma keeps a top-level list from being unrolled on return (a one-item list would
  # otherwise arrive as its item and pass a type: object check).
  return ,$r.Value
}

# ------------------------------------------------------------------ 3. JSON Schema (draft-07 subset)
# Windows PowerShell 5.1 traps this section avoids:
#   - ConvertFrom-Json returns JSON arrays as object[]. Get-SProp hands an array back whole (unary
#     comma), so wrapping a call in @() nests it one level deeper: @(Get-SProp $S 'enum') is a
#     one-element array whose only item is the whole enum. Array keywords (type, enum, required) are
#     therefore read only through Get-SList, which always returns one flat list.
#   - PSObject.Properties[...] lookups ignore case, while JSON Schema names are case-sensitive, so
#     every lookup by a data-supplied name is confirmed with -ceq.
#   - .NET regex '$' also matches before a final newline; ECMA-262 '$' (what draft-07 patterns use)
#     does not. Get-PatternRegex converts the pattern before matching.
$script:JsonTypeNames = @('null', 'boolean', 'object', 'array', 'number', 'string', 'integer')
$script:PatternCache = New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::Ordinal)

function Test-SProp($S, [string]$Name) {
  return ($null -ne $S.PSObject.Properties[$Name])
}

function Get-SProp($S, [string]$Name) {
  $p = $S.PSObject.Properties[$Name]
  if ($null -eq $p) { return $null }
  return ,$p.Value
}

# The value of a keyword as one flat list: the elements of an array value, or a single scalar value.
function Get-SList($S, [string]$Name) {
  $out = New-Object 'System.Collections.Generic.List[object]'
  $p = $S.PSObject.Properties[$Name]
  if ($null -ne $p) {
    if ($p.Value -is [System.Array]) { foreach ($x in $p.Value) { $out.Add($x) } }
    else { $out.Add($p.Value) }
  }
  return ,$out
}

function Test-IsNonNegativeInt($V) {
  if ($V -is [int] -or $V -is [long]) { return ($V -ge 0) }
  if ($V -is [double] -or $V -is [decimal]) { return ($V -ge 0 -and $V -eq [Math]::Floor($V)) }
  return $false
}

# ECMA-262 '$' without the m flag matches only at the end of the input. .NET '$' also matches before
# a final newline, so an unescaped '$' outside a character class becomes '\z'.
function Convert-EcmaPattern([string]$Pattern) {
  $sb = New-Object System.Text.StringBuilder
  $inClass = $false
  $i = 0
  while ($i -lt $Pattern.Length) {
    $ch = $Pattern[$i]
    if ($ch -ceq $script:BackslashChar) {
      [void]$sb.Append($ch)
      if (($i + 1) -lt $Pattern.Length) { [void]$sb.Append($Pattern[$i + 1]) }
      $i += 2
      continue
    }
    if ($inClass) {
      if ($ch -ceq [char]']') { $inClass = $false }
    } elseif ($ch -ceq [char]'[') {
      $inClass = $true
    } elseif ($ch -ceq [char]'$') {
      [void]$sb.Append('\z')
      $i++
      continue
    }
    [void]$sb.Append($ch)
    $i++
  }
  return $sb.ToString()
}

function Get-PatternRegex([string]$Pattern) {
  if ($script:PatternCache.ContainsKey($Pattern)) { return $script:PatternCache[$Pattern] }
  $rx = New-Object System.Text.RegularExpressions.Regex -ArgumentList (Convert-EcmaPattern $Pattern)
  $script:PatternCache[$Pattern] = $rx
  return $rx
}

function Test-SchemaKeywords($S, [string]$Where) {
  if ($null -eq $S -or $S -is [bool]) { return }
  if (-not ($S -is [System.Management.Automation.PSCustomObject])) { Stop-Run ("schema node at {0} is not a JSON object" -f $Where) }
  foreach ($p in $S.PSObject.Properties) {
    $name = $p.Name
    $v = $p.Value
    $at = $Where + '/' + $name
    if (-not $script:AllowedKeywords.Contains($name)) { Stop-Run ("schema uses the unsupported keyword '{0}' at {1}" -f $name, $Where) }
    if ($name -ceq 'properties' -or $name -ceq 'definitions') {
      if (-not ($v -is [System.Management.Automation.PSCustomObject])) { Stop-Run ("{0} must be a JSON object" -f $at) }
      foreach ($child in $v.PSObject.Properties) { Test-SchemaKeywords $child.Value ($at + '/' + $child.Name) }
    } elseif ($name -ceq 'items') {
      if ($v -is [System.Array]) { Stop-Run ("{0}: the array form of items is not supported" -f $at) }
      Test-SchemaKeywords $v $at
    } elseif ($name -ceq 'additionalProperties') {
      if (-not ($v -is [bool])) { Test-SchemaKeywords $v $at }
    } elseif ($name -ceq 'type') {
      $types = Get-SList $S 'type'
      if ($types.Count -eq 0) { Stop-Run ("{0} must not be empty" -f $at) }
      foreach ($t in $types) {
        if (-not ($t -is [string]) -or -not ($script:JsonTypeNames -ccontains $t)) { Stop-Run ("{0}: '{1}' is not a JSON Schema type name" -f $at, $t) }
      }
    } elseif ($name -ceq 'enum') {
      if (-not ($v -is [System.Array])) { Stop-Run ("{0} must be an array" -f $at) }
    } elseif ($name -ceq 'required') {
      if (-not ($v -is [System.Array])) { Stop-Run ("{0} must be an array" -f $at) }
      foreach ($r in $v) { if (-not ($r -is [string])) { Stop-Run ("{0} must contain only strings" -f $at) } }
    } elseif ($name -ceq 'pattern') {
      if (-not ($v -is [string])) { Stop-Run ("{0} must be a string" -f $at) }
      try { [void](Get-PatternRegex $v) }
      catch { Stop-Run ("{0}: '{1}' is not a valid regular expression" -f $at, $v) }
    } elseif ($name -ceq 'minLength' -or $name -ceq 'maxLength' -or $name -ceq 'minItems' -or $name -ceq 'maxItems') {
      if (-not (Test-IsNonNegativeInt $v)) { Stop-Run ("{0} must be a non-negative integer" -f $at) }
    } elseif ($name -ceq 'uniqueItems') {
      if (-not ($v -is [bool])) { Stop-Run ("{0} must be true or false" -f $at) }
    } elseif ($name -ceq '$ref') {
      if (-not ($v -is [string])) { Stop-Run ("{0} must be a string" -f $at) }
    }
  }
}

function Resolve-SchemaRef([string]$Ref) {
  $prefix = '#/definitions/'
  if (-not $Ref.StartsWith($prefix, [StringComparison]::Ordinal)) { Stop-Run ("unsupported reference '{0}'; only #/definitions/<name> is supported" -f $Ref) }
  $name = $Ref.Substring($prefix.Length)
  $defs = Get-SProp $script:SchemaRoot 'definitions'
  if ($null -eq $defs) { Stop-Run 'the schema has no definitions block' }
  $p = $defs.PSObject.Properties[$name]
  if ($null -eq $p -or $p.Name -cne $name) { Stop-Run ("schema reference '{0}' does not resolve" -f $Ref) }
  return $p.Value
}

function Get-YType($V) {
  if ($null -eq $V) { return 'null' }
  if ($V -is [string]) { return 'string' }
  if ($V -is [bool]) { return 'boolean' }
  if ($V -is [System.Collections.IDictionary]) { return 'object' }
  if ($V -is [System.Collections.IList]) { return 'array' }
  if ($V -is [int] -or $V -is [long] -or $V -is [double] -or $V -is [decimal]) { return 'number' }
  return 'unknown'
}

function Test-YType($V, [string]$Actual, [string]$Wanted) {
  if ($Wanted -ceq $Actual) { return $true }
  if ($Wanted -ceq 'integer' -and $Actual -ceq 'number') { return ([double]$V -eq [Math]::Floor([double]$V)) }
  return $false
}

# A canonical text form of any YAML or JSON value, used for JSON Schema equality (enum, const,
# uniqueItems): object key order is ignored, array order is not, and strings are length-prefixed so
# that no two different values share a form.
function Get-YCanon($V) {
  if ($null -eq $V) { return 'null' }
  if ($V -is [string]) { return 's' + $V.Length + ':' + $V }
  if ($V -is [bool]) { if ($V) { return 'true' } else { return 'false' } }
  if ($V -is [System.Collections.IDictionary] -or $V -is [System.Management.Automation.PSCustomObject]) {
    $pairs = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' -ArgumentList ([StringComparer]::Ordinal)
    if ($V -is [System.Collections.IDictionary]) { foreach ($k in $V.Keys) { $pairs[[string]$k] = Get-YCanon $V[$k] } }
    else { foreach ($p in $V.PSObject.Properties) { $pairs[$p.Name] = Get-YCanon $p.Value } }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{')
    foreach ($kv in $pairs.GetEnumerator()) { [void]$sb.Append('k' + $kv.Key.Length + ':' + $kv.Key + '=' + $kv.Value + ';') }
    [void]$sb.Append('}')
    return $sb.ToString()
  }
  if ($V -is [System.Collections.IList]) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('[')
    foreach ($x in $V) { [void]$sb.Append((Get-YCanon $x) + ',') }
    [void]$sb.Append(']')
    return $sb.ToString()
  }
  if ($V -is [int] -or $V -is [long] -or $V -is [double] -or $V -is [decimal]) {
    return 'n:' + ([double]$V).ToString('R', [Globalization.CultureInfo]::InvariantCulture)
  }
  return 'other:' + $V.GetType().FullName + ':' + [string]$V
}

function Test-YEqual($A, $B) {
  return [string]::Equals((Get-YCanon $A), (Get-YCanon $B), [StringComparison]::Ordinal)
}

# JSON Schema counts characters (code points); .NET Length counts UTF-16 units.
function Get-CodePointCount([string]$Text) {
  return $Text.Length - [regex]::Matches($Text, '[\uD800-\uDBFF][\uDC00-\uDFFF]').Count
}

# Compact JSON text for any YAML or JSON value, used to show objects and arrays in messages.
function ConvertTo-YJson($V) {
  if ($null -eq $V) { return 'null' }
  if ($V -is [bool]) { if ($V) { return 'true' } else { return 'false' } }
  if ($V -is [string]) { return (ConvertTo-JsonText $V) }
  if ($V -is [System.Collections.IDictionary]) {
    $parts = @(foreach ($k in $V.Keys) { (ConvertTo-JsonText ([string]$k)) + ':' + (ConvertTo-YJson $V[$k]) })
    return '{' + ($parts -join ',') + '}'
  }
  if ($V -is [System.Management.Automation.PSCustomObject]) {
    $parts = @(foreach ($p in $V.PSObject.Properties) { (ConvertTo-JsonText $p.Name) + ':' + (ConvertTo-YJson $p.Value) })
    return '{' + ($parts -join ',') + '}'
  }
  if ($V -is [System.Collections.IList]) {
    $parts = @(foreach ($x in $V) { ConvertTo-YJson $x })
    return '[' + ($parts -join ',') + ']'
  }
  if ($V -is [int] -or $V -is [long] -or $V -is [double] -or $V -is [decimal]) {
    return ([double]$V).ToString('R', [Globalization.CultureInfo]::InvariantCulture)
  }
  return (ConvertTo-JsonText ([string]$V))
}

function Format-YValue($V) {
  if ($null -eq $V) { return 'null' }
  if ($V -is [bool]) { if ($V) { return 'true' } else { return 'false' } }
  if ($V -is [string]) { return "'" + (Get-Short $V 60) + "'" }
  return (Get-Short (ConvertTo-YJson $V) 80)
}

function Test-SchemaNode($Node, $S, [string]$Where) {
  if ($S -is [bool]) {
    if (-not $S) { Add-Finding 'FAIL' 'schema' ("{0}: no value is allowed here" -f $Where) }
    return
  }
  if (Test-SProp $S '$ref') {
    $target = Resolve-SchemaRef ([string](Get-SProp $S '$ref'))
    Test-SchemaNode $Node $target $Where
    return
  }
  $actual = Get-YType $Node
  if (Test-SProp $S 'type') {
    $types = Get-SList $S 'type'
    $ok = $false
    foreach ($t in $types) { if (Test-YType $Node $actual ([string]$t)) { $ok = $true } }
    if (-not $ok) {
      Add-Finding 'FAIL' 'schema' ("{0}: expected {1}, found {2}" -f $Where, ($types -join ' or '), $actual)
      return
    }
  }
  if (Test-SProp $S 'const') {
    $c = Get-SProp $S 'const'
    if (-not (Test-YEqual $Node $c)) { Add-Finding 'FAIL' 'schema' ("{0}: must equal {1}, found {2}" -f $Where, (Format-YValue $c), (Format-YValue $Node)) }
  }
  if (Test-SProp $S 'enum') {
    $allowed = Get-SList $S 'enum'
    $hit = $false
    foreach ($e in $allowed) { if (Test-YEqual $Node $e) { $hit = $true; break } }
    if (-not $hit) { Add-Finding 'FAIL' 'schema' ("{0}: {1} is not an allowed value" -f $Where, (Format-YValue $Node)) }
  }
  if ($actual -ceq 'string') {
    $len = Get-CodePointCount $Node
    if (Test-SProp $S 'minLength') {
      $min = [int](Get-SProp $S 'minLength')
      if ($len -lt $min) { Add-Finding 'FAIL' 'schema' ("{0}: shorter than {1} characters" -f $Where, $min) }
    }
    if (Test-SProp $S 'maxLength') {
      $max = [int](Get-SProp $S 'maxLength')
      if ($len -gt $max) { Add-Finding 'FAIL' 'schema' ("{0}: longer than {1} characters" -f $Where, $max) }
    }
    if (Test-SProp $S 'pattern') {
      $pat = [string](Get-SProp $S 'pattern')
      if (-not (Get-PatternRegex $pat).IsMatch($Node)) { Add-Finding 'FAIL' 'schema' ("{0}: '{1}' does not match {2}" -f $Where, (Get-Short $Node 60), $pat) }
    }
  } elseif ($actual -ceq 'array') {
    $count = $Node.Count
    if (Test-SProp $S 'minItems') {
      $min = [int](Get-SProp $S 'minItems')
      if ($count -lt $min) { Add-Finding 'FAIL' 'schema' ("{0}: needs at least {1} item(s), found {2}" -f $Where, $min, $count) }
    }
    if (Test-SProp $S 'maxItems') {
      $max = [int](Get-SProp $S 'maxItems')
      if ($count -gt $max) { Add-Finding 'FAIL' 'schema' ("{0}: allows at most {1} item(s), found {2}" -f $Where, $max, $count) }
    }
    if ((Test-SProp $S 'uniqueItems') -and ((Get-SProp $S 'uniqueItems') -eq $true)) {
      $seen = New-Object 'System.Collections.Generic.Dictionary[string,int]' -ArgumentList ([StringComparer]::Ordinal)
      for ($i = 0; $i -lt $count; $i++) {
        $k = Get-YCanon $Node[$i]
        if ($seen.ContainsKey($k)) { Add-Finding 'FAIL' 'schema' ("{0}[{1}]: duplicate item {2} (same as item {3})" -f $Where, $i, (Format-YValue $Node[$i]), $seen[$k]) }
        else { $seen[$k] = $i }
      }
    }
    if (Test-SProp $S 'items') {
      $itemSchema = Get-SProp $S 'items'
      for ($i = 0; $i -lt $count; $i++) { Test-SchemaNode $Node[$i] $itemSchema ("{0}[{1}]" -f $Where, $i) }
    }
  } elseif ($actual -ceq 'object') {
    if (Test-SProp $S 'required') {
      $requiredKeys = Get-SList $S 'required'
      foreach ($r in $requiredKeys) {
        $rk = [string]$r
        if (-not $Node.Contains($rk)) { Add-Finding 'FAIL' 'schema' ("{0}: missing required key '{1}'" -f $Where, $rk) }
      }
    }
    $props = $null
    if (Test-SProp $S 'properties') { $props = Get-SProp $S 'properties' }
    $hasAddl = Test-SProp $S 'additionalProperties'
    $addl = $null
    if ($hasAddl) { $addl = Get-SProp $S 'additionalProperties' }
    foreach ($key in @($Node.Keys)) {
      $k = [string]$key
      $childSchema = $null
      if ($null -ne $props) {
        $pp = $props.PSObject.Properties[$k]
        if ($null -ne $pp -and $pp.Name -ceq $k) { $childSchema = $pp.Value }
      }
      if ($null -ne $childSchema) {
        Test-SchemaNode $Node[$key] $childSchema ($Where + '.' + $k)
      } elseif ($hasAddl) {
        if ($addl -is [bool]) {
          if (-not $addl) { Add-Finding 'FAIL' 'schema' ("{0}: unexpected key '{1}'" -f $Where, $k) }
        } else {
          Test-SchemaNode $Node[$key] $addl ($Where + '.' + $k)
        }
      }
    }
  }
}

# ------------------------------------------------------------------ 4. content rules
function Get-ExpectedHipaa {
  $map = New-Object System.Collections.Specialized.OrderedDictionary
  foreach ($line in ($script:ExpectedHipaaText -split "`r?`n")) {
    $t = $line.Trim()
    if ($t.Length -eq 0) { continue }
    $parts = $t.Split([char]'|')
    if ($parts.Length -ne 4) { Stop-Run ("internal list error near '{0}'" -f $t) }
    $map[$parts[0]] = @{ Kind = $parts[1]; Designation = $parts[2]; Title = $parts[3] }
  }
  return $map
}

function Test-KeySet($List, [string[]]$Expected, [string]$Where) {
  $seen = New-StringSet
  foreach ($item in $List) {
    $k = [string]$item['key']
    if (-not $seen.Add($k)) { Add-Finding 'FAIL' 'content' ("{0}: duplicate key '{1}'" -f $Where, $k) }
  }
  $want = Get-SortedJoin $Expected
  $have = Get-SortedJoin $seen
  if ($want -cne $have) { Add-Finding 'FAIL' 'content' ("{0}: keys must be exactly [{1}], found [{2}]" -f $Where, $want, $have) }
}

# True when Text names Id as a whole identifier: 'Requirement 11.2.3' does not name 1.2.3,
# 'Requirement 9.5.1.2' does not name 9.5.1, and '164.312(a)(1)(i)' does not name 164.312(a)(1).
# A sentence-ending period, or a testing-procedure suffix such as 1.2.3.a, is allowed.
function Test-NamesId([string]$Text, [string]$Id) {
  $rx = '(?<![A-Za-z0-9.])' + [regex]::Escape($Id) + '(?![A-Za-z0-9(]|\.[0-9])'
  return [regex]::IsMatch($Text, $rx)
}

function Test-Citation($Citation, $SourceKeys, [string]$Where, [string]$MustContain) {
  $src = [string]$Citation['source']
  if (-not $SourceKeys.Contains($src)) { Add-Finding 'FAIL' 'content' ("{0}: citation source '{1}' is not in metadata.sources" -f $Where, $src) }
  if ($MustContain.Length -gt 0) {
    $loc = [string]$Citation['locator']
    if (-not (Test-NamesId $loc $MustContain)) { Add-Finding 'FAIL' 'content' ("{0}: citation locator '{1}' does not name {2}" -f $Where, $loc, $MustContain) }
  }
}

function Test-Content($Doc) {
  $meta = $Doc['metadata']
  $maps = $Doc['mappings']

  Test-KeySet $meta['relationship_types'] @('equivalent', 'partial', 'related') 'metadata.relationship_types'
  Test-KeySet $meta['coverage_types'] @('designed', 'partial', 'procedural', 'out-of-scope', 'not-applicable') 'metadata.coverage_types'
  Test-KeySet $meta['applicability_types'] @('applicable', 'indirect', 'not-applicable') 'metadata.applicability_types'
  Test-KeySet $meta['pci_path_statuses'] @('required', 'performed-anyway', 'defense-in-depth', 'not-applicable-by-design', 'not-on-saq-p2pe') 'metadata.pci_path_statuses'
  Test-KeySet $meta['frameworks'] @('hipaa-security-rule', 'nist-csf', 'pci-dss') 'metadata.frameworks'

  $hipaaVersion = ''
  foreach ($fw in $meta['frameworks']) { if ([string]$fw['key'] -ceq 'hipaa-security-rule') { $hipaaVersion = [string]$fw['version'] } }

  $sourceKeys = New-StringSet
  foreach ($s in $meta['sources']) {
    $k = [string]$s['key']
    if (-not $sourceKeys.Add($k)) { Add-Finding 'FAIL' 'content' ("metadata.sources: duplicate key '{0}'" -f $k) }
  }
  foreach ($k in $meta['hitrust']['sources']) {
    if (-not $sourceKeys.Contains([string]$k)) { Add-Finding 'FAIL' 'content' ("metadata.hitrust.sources: '{0}' is not in metadata.sources" -f $k) }
  }

  $csfCatalog = New-StringSet
  foreach ($c in $meta['csf_subcategories']) {
    $id = [string]$c['id']
    if (-not $csfCatalog.Add($id)) { Add-Finding 'FAIL' 'content' ("metadata.csf_subcategories: duplicate id '{0}'" -f $id) }
  }
  $pciCatalog = New-StringSet
  foreach ($p in $meta['pci_requirements']) {
    $id = [string]$p['id']
    if (-not $pciCatalog.Add($id)) { Add-Finding 'FAIL' 'content' ("metadata.pci_requirements: duplicate id '{0}'" -f $id) }
    foreach ($v in $p['verified_against']) {
      if (-not $sourceKeys.Contains([string]$v)) { Add-Finding 'FAIL' 'content' ("metadata.pci_requirements {0}: source '{1}' is not in metadata.sources" -f $id, $v) }
    }
  }

  $expected = Get-ExpectedHipaa
  $seenRowIds = New-StringSet
  $seenHipaa = New-StringSet
  $usedCsf = New-StringSet
  $usedPci = New-StringSet

  for ($i = 0; $i -lt $maps.Count; $i++) {
    $m = $maps[$i]
    $rowId = [string]$m['id']
    $where = 'mappings[' + $i + '] ' + $rowId
    if (-not $seenRowIds.Add($rowId)) { Add-Finding 'FAIL' 'content' ("{0}: duplicate mapping id" -f $where) }

    $src = $m['source']
    $hid = [string]$src['id']
    $where = $where + ' (' + $hid + ')'
    if (-not $seenHipaa.Add($hid)) { Add-Finding 'FAIL' 'content' ("{0}: this HIPAA provision already has a row" -f $where) }
    if ($expected.Contains($hid)) {
      $exp = $expected[$hid]
      if ([string]$src['kind'] -cne $exp.Kind) { Add-Finding 'FAIL' 'content' ("{0}: kind must be '{1}'" -f $where, $exp.Kind) }
      if ([string]$src['designation'] -cne $exp.Designation) { Add-Finding 'FAIL' 'content' ("{0}: designation must be '{1}'" -f $where, $exp.Designation) }
      if ([string]$src['title'] -cne $exp.Title) { Add-Finding 'FAIL' 'content' ("{0}: title must be '{1}'" -f $where, $exp.Title) }
    } else {
      Add-Finding 'FAIL' 'content' ("{0}: not a standard or implementation specification in 45 CFR 164.308 to 164.316" -f $where)
    }
    if ([string]$src['framework_version'] -cne $hipaaVersion) { Add-Finding 'FAIL' 'content' ("{0}: source.framework_version differs from the hipaa-security-rule version in metadata.frameworks" -f $where) }
    $sectionKey = 'SRC-ECFR-' + $hid.Substring(0, 7).Replace('.', '-')
    if ([string]$src['citation']['source'] -cne $sectionKey) { Add-Finding 'FAIL' 'content' ("{0}: source citation should be {1}" -f $where, $sectionKey) }
    Test-Citation $src['citation'] $sourceKeys ($where + ' source') $hid

    $app = [string]$m['applicability']
    $cov = [string]$m['coverage']
    $csf = $m['csf_targets']
    $pci = $m['pci_targets']
    $cde = [bool]$m['cde_scope']
    $arch = $m['architecture']
    if ($app -ceq 'not-applicable') {
      if ($cov -cne 'not-applicable') { Add-Finding 'FAIL' 'content' ("{0}: a not-applicable row must have coverage 'not-applicable'" -f $where) }
      if ($csf.Count -gt 0) { Add-Finding 'FAIL' 'content' ("{0}: a not-applicable row carries no CSF targets" -f $where) }
      if ($pci.Count -gt 0 -or $cde) { Add-Finding 'FAIL' 'content' ("{0}: a not-applicable row carries no PCI DSS targets" -f $where) }
    } else {
      if ($cov -ceq 'not-applicable') { Add-Finding 'FAIL' 'content' ("{0}: coverage 'not-applicable' needs applicability 'not-applicable'" -f $where) }
      if ($csf.Count -eq 0) { Add-Finding 'FAIL' 'content' ("{0}: an applicable row needs at least one CSF 2.0 target" -f $where) }
    }
    if ($app -ceq 'indirect' -and $cov -ceq 'designed') { Add-Finding 'FAIL' 'content' ("{0}: an indirect row cannot be 'designed'" -f $where) }
    if ($cov -ceq 'designed' -and $arch['components'].Count -eq 0) { Add-Finding 'FAIL' 'content' ("{0}: coverage 'designed' must name at least one component" -f $where) }

    $localCsf = New-StringSet
    foreach ($t in $csf) {
      $cid = [string]$t['id']
      if (-not $localCsf.Add($cid)) { Add-Finding 'FAIL' 'content' ("{0}: CSF target {1} appears twice" -f $where, $cid) }
      if (-not $csfCatalog.Contains($cid)) { Add-Finding 'FAIL' 'content' ("{0}: CSF target {1} is not in metadata.csf_subcategories" -f $where, $cid) }
      [void]$usedCsf.Add($cid)
      Test-Citation $t['citation'] $sourceKeys ($where + ' CSF ' + $cid) $cid
    }

    if ($cde) {
      if ($pci.Count -eq 0) { Add-Finding 'FAIL' 'content' ("{0}: cde_scope is true but there are no PCI DSS targets" -f $where) }
      $hasCde = $false
      foreach ($z in $arch['zones']) { if ([string]$z -ceq 'Z-CDE') { $hasCde = $true } }
      foreach ($c in $arch['components']) { if ($script:CdeComponents -ccontains [string]$c) { $hasCde = $true } }
      if (-not $hasCde) { Add-Finding 'FAIL' 'content' ("{0}: cde_scope is true but the row references neither zone Z-CDE nor a CDE component ({1})" -f $where, ($script:CdeComponents -join ', ')) }
    } elseif ($pci.Count -gt 0) {
      Add-Finding 'FAIL' 'content' ("{0}: PCI DSS targets are allowed only on rows with cde_scope true (Z-CDE segment only)" -f $where)
    }
    $localPci = New-StringSet
    foreach ($t in $pci) {
      $pciId = [string]$t['id']
      if (-not $localPci.Add($pciId)) { Add-Finding 'FAIL' 'content' ("{0}: PCI DSS target {1} appears twice" -f $where, $pciId) }
      if (-not $pciCatalog.Contains($pciId)) { Add-Finding 'FAIL' 'content' ("{0}: PCI DSS target {1} is not in metadata.pci_requirements" -f $where, $pciId) }
      [void]$usedPci.Add($pciId)
      foreach ($sc in $t['shared_csf']) {
        if (-not $csfCatalog.Contains([string]$sc)) { Add-Finding 'FAIL' 'content' ("{0}: shared CSF {1} on PCI DSS {2} is not in metadata.csf_subcategories" -f $where, $sc, $pciId) }
        [void]$usedCsf.Add([string]$sc)
      }
      Test-Citation $t['citation'] $sourceKeys ($where + ' PCI ' + $pciId) $pciId
    }
  }

  foreach ($k in @($expected.Keys)) {
    if (-not $seenHipaa.Contains([string]$k)) { Add-Finding 'FAIL' 'content' ("missing a row for 45 CFR {0} ({1})" -f $k, $expected[$k].Title) }
  }
  foreach ($c in $csfCatalog) {
    if (-not $usedCsf.Contains($c)) { Add-Finding 'WARN' 'content' ("metadata.csf_subcategories: {0} is not used by any row" -f $c) }
  }
  foreach ($p in $pciCatalog) {
    if (-not $usedPci.Contains($p)) { Add-Finding 'WARN' 'content' ("metadata.pci_requirements: {0} is not used by any row" -f $p) }
  }
}

# ------------------------------------------------------------------ 5. cross-file references
function Split-MdRow([string]$Row) {
  $t = $Row.Trim()
  if ($t.StartsWith('|', [StringComparison]::Ordinal)) { $t = $t.Substring(1) }
  if ($t.EndsWith('|', [StringComparison]::Ordinal)) { $t = $t.Substring(0, $t.Length - 1) }
  $out = New-Object 'System.Collections.Generic.List[string]'
  foreach ($part in $t.Split([char]'|')) { $out.Add($part.Trim()) }
  return ,$out
}

function Get-Headings([string]$File) {
  if ($script:HeadingCache.ContainsKey($File)) { return ,$script:HeadingCache[$File] }
  $list = New-Object 'System.Collections.Generic.List[string]'
  $inFence = $false
  foreach ($raw in (Get-FileLines $File)) {
    if ([regex]::IsMatch($raw, '^\s{0,3}(```|~~~)')) { $inFence = -not $inFence; continue }
    if ($inFence) { continue }
    $m = [regex]::Match($raw, '^#{1,6}\s+(.*?)\s*#*\s*$')
    if ($m.Success) { $list.Add($m.Groups[1].Value.Trim()) }
  }
  $script:HeadingCache[$File] = $list
  return ,$list
}

function Test-HasSection([string]$File, [string]$Section) {
  $heads = Get-Headings $File
  if ([regex]::IsMatch($Section, '^[0-9]+(\.[0-9]+)*$')) {
    $rx = '^' + [regex]::Escape($Section) + '\.(\s|$)'
    foreach ($h in $heads) { if ([regex]::IsMatch($h, $rx)) { return $true } }
    return $false
  }
  foreach ($h in $heads) { if ([string]::Equals($h, $Section.Trim(), [StringComparison]::OrdinalIgnoreCase)) { return $true } }
  return $false
}

function Get-TableIds([string]$File, [string]$Heading, [string]$IdPattern) {
  $set = New-StringSet
  $inSection = $false
  $level = 0
  $inFence = $false
  foreach ($raw in (Get-FileLines $File)) {
    if ([regex]::IsMatch($raw, '^\s{0,3}(```|~~~)')) { $inFence = -not $inFence; continue }
    if ($inFence) { continue }
    $m = [regex]::Match($raw, '^(#{1,6})\s+(.*?)\s*$')
    if ($m.Success) {
      $lvl = $m.Groups[1].Value.Length
      if ($inSection -and $lvl -le $level) { $inSection = $false }
      if (-not $inSection -and $m.Groups[2].Value.IndexOf($Heading, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $inSection = $true
        $level = $lvl
      }
      continue
    }
    if (-not $inSection) { continue }
    $t = $raw.Trim()
    if (-not $t.StartsWith('|', [StringComparison]::Ordinal)) { continue }
    $cells = Split-MdRow $t
    if ($cells.Count -eq 0) { continue }
    $first = $cells[0].Replace('`', '').Trim()
    if ([regex]::IsMatch($first, $IdPattern)) { [void]$set.Add($first) }
  }
  return ,$set
}

function Test-CrossFile($Doc, [string]$BaseDir) {
  $paths = $Doc['metadata']['paths']
  $roots = @{}
  foreach ($k in @($paths.Keys)) {
    $rel = ([string]$paths[$k]).Replace('/', '\')
    $roots[[string]$k] = [IO.Path]::GetFullPath([IO.Path]::Combine($BaseDir, $rel))
  }
  $archRoot = $roots['architecture']
  if (-not [IO.Directory]::Exists($archRoot)) {
    Add-Finding 'FAIL' 'files' ("architecture folder not found: {0} (update metadata.paths, or use -SkipFileChecks to check structure only)" -f $archRoot)
    return
  }
  $f02 = [IO.Path]::Combine($archRoot, '02-reference-architecture.md')
  $f03 = [IO.Path]::Combine($archRoot, '03-identity-and-access.md')
  $f04 = [IO.Path]::Combine($archRoot, '04-segmentation.md')
  foreach ($f in @($f02, $f03, $f04)) {
    if (-not [IO.File]::Exists($f)) { Add-Finding 'FAIL' 'files' ("required architecture file not found: {0}" -f $f); return }
  }

  $components = Get-TableIds $f02 'Component glossary' '^(PE|PA|IGA|PEP|IDS|PIP|SVC|RES|EXT)-[A-Z0-9]+(-[A-Z0-9]+)*$'
  $zones = Get-TableIds $f02 'Trust zones' '^Z-[A-Z0-9]+(-[A-Z0-9]+)*$'
  foreach ($z in (Get-TableIds $f04 'Device-class segments' '^Z-[A-Z0-9]+(-[A-Z0-9]+)*$')) { [void]$zones.Add($z) }
  $policies = Get-TableIds $f03 'Reference Conditional Access policy set' '^CA-[0-9]{2}$'
  $flows = Get-TableIds $f02 'Key data flows' '^F-[0-9]{2}$'
  $risks = Get-TableIds $f02 'What this architecture does not solve' '^RR-[0-9]{2}$'
  $sets = @(
    @{ Name = 'component glossary (02, Component glossary)'; Set = $components; Key = 'components' },
    @{ Name = 'zones (02, Trust zones; 04, Device-class segments)'; Set = $zones; Key = 'zones' },
    @{ Name = 'Conditional Access policies (03, Reference Conditional Access policy set)'; Set = $policies; Key = 'policies' },
    @{ Name = 'data flows (02, Key data flows)'; Set = $flows; Key = 'flows' },
    @{ Name = 'residual risks (02, What this architecture does not solve)'; Set = $risks; Key = 'residual_risks' }
  )
  foreach ($s in $sets) {
    if ($s.Set.Count -eq 0) { Add-Finding 'FAIL' 'files' ("could not read any IDs for the {0}" -f $s.Name) }
  }

  $usedComponents = New-StringSet
  $detectionCount = 0
  $maps = $Doc['mappings']
  foreach ($m in $maps) {
    $where = [string]$m['id']
    $arch = $m['architecture']
    foreach ($s in $sets) {
      foreach ($id in $arch[$s.Key]) {
        $v = [string]$id
        if ($s.Key -ceq 'components') { [void]$usedComponents.Add($v) }
        if ($s.Set.Count -gt 0 -and -not $s.Set.Contains($v)) { Add-Finding 'FAIL' 'files' ("{0}: {1} is not defined in the {2}" -f $where, $v, $s.Name) }
      }
    }
    foreach ($a in $arch['artifacts']) {
      $docKey = [string]$a['doc']
      if (-not $roots.ContainsKey($docKey)) { Add-Finding 'FAIL' 'files' ("{0}: artifact doc '{1}' has no entry in metadata.paths" -f $where, $docKey); continue }
      $file = [IO.Path]::Combine($roots[$docKey], ([string]$a['file']).Replace('/', '\'))
      if (-not [IO.File]::Exists($file)) { Add-Finding 'FAIL' 'files' ("{0}: file not found: {1}" -f $where, $file); continue }
      $section = [string]$a['section']
      if (-not (Test-HasSection $file $section)) { Add-Finding 'FAIL' 'files' ("{0}: no heading for section '{1}' in {2}" -f $where, $section, $a['file']) }
    }
    foreach ($d in $m['detections']) {
      $detectionCount++
      if (-not $roots.ContainsKey('detections')) { Add-Finding 'FAIL' 'files' ("{0}: detections are listed but metadata.paths has no detections entry" -f $where); continue }
      $file = [IO.Path]::Combine($roots['detections'], ([string]$d['file']).Replace('/', '\'))
      if (-not [IO.File]::Exists($file)) { Add-Finding 'FAIL' 'files' ("{0}: detection file not found: {1}" -f $where, $file) }
    }
  }
  if ($detectionCount -eq 0) { Add-Finding 'INFO' 'files' 'no detections are linked yet; the detections fields fill in once the detection pack exists' }
  $unused = @(foreach ($c in $components) { if (-not $usedComponents.Contains($c)) { $c } })
  if ($unused.Count -gt 0) {
    Add-Finding 'INFO' 'files' ("{0} glossary component(s) are not referenced by any row: {1}" -f $unused.Count, (Get-SortedJoin $unused))
  }
}

# ------------------------------------------------------------------ 6. crosswalk.md agreement
function Get-HeaderIndex($Header, [string]$Name) {
  for ($i = 0; $i -lt $Header.Count; $i++) { if ($Header[$i] -ceq $Name) { return $i } }
  return -1
}

function Get-MdCsfSet([string]$Cell) {
  $list = New-Object 'System.Collections.Generic.List[string]'
  foreach ($m in [regex]::Matches($Cell, '([A-Z]{2}\.[A-Z]{2}-[0-9]{2})\s*\((equivalent|partial|related)\)')) {
    $list.Add($m.Groups[1].Value + ' ' + $m.Groups[2].Value)
  }
  return ,$list
}

function Get-MdPciSet([string]$Cell) {
  $list = New-Object 'System.Collections.Generic.List[string]'
  $t = $Cell.Trim()
  if ($t.Length -eq 0 -or $t -ceq 'none') { return ,$list }
  foreach ($m in [regex]::Matches($t, '(?<![0-9.])[0-9]{1,2}(\.[0-9]{1,2}){1,4}(?![0-9])')) { $list.Add($m.Value) }
  return ,$list
}

function Test-Markdown($Doc, [string]$MdPath, [string]$YamlName) {
  # Messages name the files actually compared, which differ from crosswalk.md and crosswalk.yaml
  # when -Markdown or -Path point elsewhere (for example at test fixtures).
  $mdName = [IO.Path]::GetFileName($MdPath)
  if (-not [IO.File]::Exists($MdPath)) { Add-Finding 'WARN' 'markdown' ("{0} not found at {1}; agreement check skipped" -f $mdName, $MdPath); return }
  # Ordinal keys: a PowerShell @{} ignores case, which would match a crosswalk.md row for
  # 164.308(a)(1)(ii)(a) to the YAML row for 164.308(a)(1)(ii)(A).
  $byId = New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::Ordinal)
  foreach ($m in $Doc['mappings']) { $byId[[string]$m['source']['id']] = $m }
  $seen = New-StringSet
  $lines = Get-FileLines $MdPath
  $header = $null
  $rowsChecked = 0
  for ($i = 0; $i -lt $lines.Length; $i++) {
    $t = $lines[$i].Trim()
    if (-not $t.StartsWith('|', [StringComparison]::Ordinal)) { $header = $null; continue }
    if ($null -eq $header) {
      if (($i + 1) -lt $lines.Length -and [regex]::IsMatch($lines[$i + 1].Trim(), '^\|(\s*:?-{3,}:?\s*\|)+\s*$')) {
        $header = Split-MdRow $t
        $i++
      }
      continue
    }
    $hIdx = Get-HeaderIndex $header $script:MdHipaaHeader
    $cIdx = Get-HeaderIndex $header $script:MdCsfHeader
    $vIdx = Get-HeaderIndex $header $script:MdCoverageHeader
    $pIdx = Get-HeaderIndex $header $script:MdPciHeader
    if ($hIdx -lt 0 -or $cIdx -lt 0 -or $vIdx -lt 0 -or $pIdx -lt 0) { continue }
    $lineNo = $i + 1
    $cells = Split-MdRow $t
    if ($cells.Count -ne $header.Count) { Add-Finding 'FAIL' 'markdown' ("{0} line {1}: expected {2} cells, found {3}" -f $mdName, $lineNo, $header.Count, $cells.Count); continue }
    $mm = [regex]::Match($cells[$hIdx], '164\.3[0-9]{2}(\([0-9A-Za-z]+\))+')
    if (-not $mm.Success) { Add-Finding 'FAIL' 'markdown' ("{0} line {1}: no HIPAA citation in the first column" -f $mdName, $lineNo); continue }
    $hid = $mm.Value
    $rowsChecked++
    if (-not $seen.Add($hid)) { Add-Finding 'FAIL' 'markdown' ("{0} line {1}: second row for {2}" -f $mdName, $lineNo, $hid); continue }
    if (-not $byId.ContainsKey($hid)) { Add-Finding 'FAIL' 'markdown' ("{0} line {1}: {2} has no row in {3}" -f $mdName, $lineNo, $hid, $YamlName); continue }
    $map = $byId[$hid]

    $yCsf = @(foreach ($tg in $map['csf_targets']) { [string]$tg['id'] + ' ' + [string]$tg['relationship'] })
    $mCsf = Get-MdCsfSet $cells[$cIdx]
    $yJoin = Get-SortedJoin $yCsf
    $mJoin = Get-SortedJoin $mCsf
    if ($yJoin -cne $mJoin) { Add-Finding 'FAIL' 'markdown' ("{0} line {1} ({2}): CSF targets [{3}] differ from {4} [{5}]" -f $mdName, $lineNo, $hid, $mJoin, $YamlName, $yJoin) }

    $mCov = $cells[$vIdx].Replace('`', '').Trim()
    if ($mCov -cne [string]$map['coverage']) { Add-Finding 'FAIL' 'markdown' ("{0} line {1} ({2}): coverage '{3}' differs from {4} '{5}'" -f $mdName, $lineNo, $hid, $mCov, $YamlName, $map['coverage']) }

    $yPci = @(foreach ($tg in $map['pci_targets']) { [string]$tg['id'] })
    $mPci = Get-MdPciSet $cells[$pIdx]
    $yPJoin = Get-SortedJoin $yPci
    $mPJoin = Get-SortedJoin $mPci
    if ($yPJoin -cne $mPJoin) { Add-Finding 'FAIL' 'markdown' ("{0} line {1} ({2}): PCI DSS targets [{3}] differ from {4} [{5}]" -f $mdName, $lineNo, $hid, $mPJoin, $YamlName, $yPJoin) }
  }
  if ($rowsChecked -eq 0) {
    Add-Finding 'FAIL' 'markdown' ("no crosswalk table found in {0} (a table needs the headers '{1}', '{2}', '{3}', and '{4}')" -f $mdName, $script:MdHipaaHeader, $script:MdCsfHeader, $script:MdCoverageHeader, $script:MdPciHeader)
    return
  }
  foreach ($k in @($byId.Keys)) {
    if (-not $seen.Contains([string]$k)) { Add-Finding 'FAIL' 'markdown' ("{0} has no row for {1}" -f $mdName, $k) }
  }
}

# ------------------------------------------------------------------ statistics
function Get-Stats($Doc) {
  $rows = 0; $applicable = 0; $indirect = 0; $notApplicable = 0
  $designed = 0; $partialCoverage = 0; $procedural = 0; $outOfScope = 0; $coverageNa = 0
  $csfLinks = 0; $equivalent = 0; $partial = 0; $related = 0
  $cdeRows = 0; $pciLinks = 0; $detectionsLinked = 0
  $csfUsed = New-StringSet
  foreach ($m in $Doc['mappings']) {
    $rows++
    $a = [string]$m['applicability']
    if ($a -ceq 'applicable') { $applicable++ } elseif ($a -ceq 'indirect') { $indirect++ } elseif ($a -ceq 'not-applicable') { $notApplicable++ }
    $c = [string]$m['coverage']
    if ($c -ceq 'designed') { $designed++ }
    elseif ($c -ceq 'partial') { $partialCoverage++ }
    elseif ($c -ceq 'procedural') { $procedural++ }
    elseif ($c -ceq 'out-of-scope') { $outOfScope++ }
    elseif ($c -ceq 'not-applicable') { $coverageNa++ }
    foreach ($t in $m['csf_targets']) {
      $csfLinks++
      [void]$csfUsed.Add([string]$t['id'])
      $rel = [string]$t['relationship']
      if ($rel -ceq 'equivalent') { $equivalent++ } elseif ($rel -ceq 'partial') { $partial++ } elseif ($rel -ceq 'related') { $related++ }
    }
    if ([bool]$m['cde_scope']) { $cdeRows++ }
    $pciLinks = $pciLinks + $m['pci_targets'].Count
    $detectionsLinked = $detectionsLinked + $m['detections'].Count
  }
  $stats = New-Object System.Collections.Specialized.OrderedDictionary
  $stats['rows'] = $rows
  $stats['applicable'] = $applicable
  $stats['indirect'] = $indirect
  $stats['not_applicable'] = $notApplicable
  $stats['designed'] = $designed
  $stats['partial_coverage'] = $partialCoverage
  $stats['procedural'] = $procedural
  $stats['out_of_scope'] = $outOfScope
  $stats['coverage_not_applicable'] = $coverageNa
  $stats['csf_links'] = $csfLinks
  $stats['equivalent'] = $equivalent
  $stats['partial'] = $partial
  $stats['related'] = $related
  $stats['csf_subcategories_used'] = $csfUsed.Count
  $stats['cde_rows'] = $cdeRows
  $stats['pci_links'] = $pciLinks
  $stats['detections_linked'] = $detectionsLinked
  return $stats
}

# ------------------------------------------------------------------ main
$exitCode = 2
$yamlPath = ''
$stats = $null
try {
  $scriptDir = $PSScriptRoot
  if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
  if (-not $Path) { $Path = [IO.Path]::Combine($scriptDir, 'crosswalk.yaml') }
  if (-not $Schema) { $Schema = [IO.Path]::Combine($scriptDir, 'crosswalk.schema.json') }
  $yamlPath = Resolve-FullPath $Path
  $schemaPath = Resolve-FullPath $Schema
  if (-not [IO.File]::Exists($yamlPath)) { Stop-Run ("crosswalk file not found: {0}" -f $yamlPath) }
  if (-not [IO.File]::Exists($schemaPath)) { Stop-Run ("schema file not found: {0}" -f $schemaPath) }
  $yamlDir = [IO.Path]::GetDirectoryName($yamlPath)
  if (-not $Markdown) { $Markdown = [IO.Path]::Combine($yamlDir, 'crosswalk.md') }
  $mdPath = Resolve-FullPath $Markdown

  $schemaText = [IO.File]::ReadAllText($schemaPath, [Text.Encoding]::UTF8)
  try { $script:SchemaRoot = $schemaText | ConvertFrom-Json }
  catch { Stop-Run ("the schema is not valid JSON: {0}" -f $_.Exception.Message) }
  Test-SchemaKeywords $script:SchemaRoot '#'

  $yamlText = [IO.File]::ReadAllText($yamlPath, [Text.Encoding]::UTF8)
  Test-TextHygiene ([regex]::Split($yamlText, '\r\n|\n|\r'))

  $doc = $null
  try { $doc = ConvertFrom-YamlSubset $yamlText }
  catch [System.FormatException] { Add-Finding 'FAIL' 'yaml' $_.Exception.Message }

  if ($null -ne $doc) {
    Test-SchemaNode $doc $script:SchemaRoot '$'
    $schemaFails = @($script:Findings | Where-Object { $_.severity -ceq 'FAIL' -and $_.check -ceq 'schema' }).Count
    if ($schemaFails -eq 0) {
      Test-Content $doc
      if ($SkipFileChecks) { Add-Finding 'WARN' 'files' 'cross-file checks skipped (-SkipFileChecks)' }
      else { Test-CrossFile $doc $yamlDir }
      if ($SkipMarkdown) { Add-Finding 'WARN' 'markdown' 'crosswalk.md agreement check skipped (-SkipMarkdown)' }
      else { Test-Markdown $doc $mdPath ([IO.Path]::GetFileName($yamlPath)) }
      $stats = Get-Stats $doc
    } else {
      Add-Finding 'WARN' 'schema' 'content, file, and markdown checks were skipped because the structure is invalid; fix the schema findings first'
    }
  }

  $fails = @($script:Findings | Where-Object { $_.severity -ceq 'FAIL' }).Count
  $warns = @($script:Findings | Where-Object { $_.severity -ceq 'WARN' }).Count
  if ($fails -gt 0) { $exitCode = 1 } else { $exitCode = 0 }

  if ($Json) {
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($f in $script:Findings) {
      $parts.Add('{"severity":' + (ConvertTo-JsonText $f.severity) + ',"check":' + (ConvertTo-JsonText $f.check) + ',"message":' + (ConvertTo-JsonText $f.message) + '}')
    }
    $statText = '{}'
    if ($null -ne $stats) {
      $sp = @(foreach ($k in $stats.Keys) { (ConvertTo-JsonText ([string]$k)) + ':' + [string]$stats[$k] })
      $statText = '{' + ($sp -join ',') + '}'
    }
    $out = '{"tool":"validate-crosswalk","path":' + (ConvertTo-JsonText $yamlPath) + ',"fails":' + $fails + ',"warns":' + $warns + ',"findings":[' + ($parts -join ',') + '],"stats":' + $statText + '}'
    Write-Output $out
  } else {
    Write-Output ('validate-crosswalk: ' + $yamlPath)
    foreach ($f in $script:Findings) { Write-Output ('{0} [{1}] {2}' -f $f.severity, $f.check, $f.message) }
    if ($null -ne $stats) {
      Write-Output ''
      Write-Output ('Rows: {0} (applicable {1}, indirect {2}, not applicable {3})' -f $stats.rows, $stats.applicable, $stats.indirect, $stats.not_applicable)
      Write-Output ('Coverage: designed {0}, partial {1}, procedural {2}, out of scope {3}, not applicable {4}' -f $stats.designed, $stats.partial_coverage, $stats.procedural, $stats.out_of_scope, $stats.coverage_not_applicable)
      Write-Output ('CSF 2.0 links: {0} (equivalent {1}, partial {2}, related {3}); distinct subcategories {4}' -f $stats.csf_links, $stats.equivalent, $stats.partial, $stats.related, $stats.csf_subcategories_used)
      Write-Output ('PCI DSS v4.0.1 links: {0} on {1} CDE-scoped rows; detections linked: {2}' -f $stats.pci_links, $stats.cde_rows, $stats.detections_linked)
    }
    if ($exitCode -eq 0) { Write-Output ('Result: PASS ({0} warning(s))' -f $warns) }
    else { Write-Output ('Result: FAIL ({0} failure(s), {1} warning(s))' -f $fails, $warns) }
  }
} catch {
  $msg = $_.Exception.Message
  $exitCode = 2
  if ($Json) {
    Write-Output ('{"tool":"validate-crosswalk","path":' + (ConvertTo-JsonText $yamlPath) + ',"fails":0,"warns":0,"findings":[],"error":' + (ConvertTo-JsonText $msg) + '}')
    [Console]::Error.WriteLine($msg)
  } else {
    Write-Output ('validate-crosswalk could not run: ' + $msg)
  }
}
exit $exitCode
