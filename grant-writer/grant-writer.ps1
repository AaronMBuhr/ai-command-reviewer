param([string]$Action, [string]$ForUser, [string]$Name, [string]$GrantsPath,
      [string]$RequestFile, [string]$GrantsFile, [string]$AclFile, [string]$OldFile,
      [string]$NewFile, [string]$Now, [switch]$LibraryOnly)
$ErrorActionPreference = 'Stop'   # a variable assignment, not a cmdlet

# Exception-grant writer. See exception-grants-design.md sections 6-7 and
# exception-grants-implementation-plan.md section 7.
#
# This script runs ELEVATED (after a UAC prompt), so it follows strict rules:
#   * No cmdlets at all, not even Set-StrictMode or Write-Host: cmdlets can be
#     auto-loaded from user-writable module folders. Only language keywords,
#     .NET calls, and functions/classes defined in this file.
#     tests/ps/check-no-cmdlets.ps1 enforces this with PowerShell's own parser.
#   * It never reads the user's config, never runs Git, never starts a process.
#   * It reads the request from the clipboard itself.
#
# Validation mirrors .claude/hooks/exception_grants.py rule for rule and in the
# same order. The shared fixtures in tests/fixtures/ keep the two in step.

# Full names only, so the assemblies come from the protected Global Assembly Cache.
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')

# ==========================================================================
# JSON
# ==========================================================================

# A JSON number, kept as its raw text so `v` can be checked as exactly 1.
class JsonNumber {
    [string]$Text
    [bool]$IsInteger
    JsonNumber([string]$text, [bool]$isInteger) { $this.Text = $text; $this.IsInteger = $isInteger }
}

# A strict recursive-descent parser accepting exactly what Python's json module
# accepts (decision D16), plus our extra rules: NaN/Infinity rejected, duplicate
# keys reported when their object closes (as Python's object_pairs_hook does).
# On failure it sets Code/Field and throws FormatException.
class JsonParser {
    [string]$S
    [int]$I
    [string]$Code
    [object]$Field

    JsonParser([string]$s) { $this.S = $s; $this.I = 0 }

    [void] Fail([string]$code, [object]$field) {
        $this.Code = $code
        $this.Field = $field
        throw [System.FormatException]::new($code)
    }

    [bool] IsWs([int]$c) { return $c -eq 0x20 -or $c -eq 0x09 -or $c -eq 0x0A -or $c -eq 0x0D }

    [void] SkipWs() {
        while ($this.I -lt $this.S.Length -and $this.IsWs([int]$this.S[$this.I])) { $this.I++ }
    }

    [int] Peek() {
        if ($this.I -ge $this.S.Length) { return -1 }
        return [int]$this.S[$this.I]
    }

    [bool] At([string]$word) {
        return [string]::CompareOrdinal($this.S, $this.I, $word, 0, $word.Length) -eq 0 -and
               $this.I + $word.Length -le $this.S.Length
    }

    # Parse one complete document: optional whitespace, one value, whitespace.
    [object] ParseDocument() {
        $this.SkipWs()
        $value = $this.ParseValue()
        $this.SkipWs()
        if ($this.I -ne $this.S.Length) { $this.Fail('json-syntax', $null) }
        return $value
    }

    [object] ParseValue() {
        $c = $this.Peek()
        if ($c -eq 0x7B) { return $this.ParseObject() }
        if ($c -eq 0x5B) { return $this.ParseArray() }
        if ($c -eq 0x22) { return $this.ParseString() }
        if ($this.At('true')) { $this.I += 4; return $true }
        if ($this.At('false')) { $this.I += 5; return $false }
        if ($this.At('null')) { $this.I += 4; return $null }
        if ($c -eq 0x2D -or ($c -ge 0x30 -and $c -le 0x39)) { return $this.ParseNumber() }
        # NaN, Infinity and anything else: strict JSON forbids them.
        $this.Fail('json-syntax', $null)
        return $null
    }

    [bool] IsDigit([int]$c) { return $c -ge 0x30 -and $c -le 0x39 }

    [object] ParseNumber() {
        $start = $this.I
        if ($this.Peek() -eq 0x2D) { $this.I++ }
        $c = $this.Peek()
        if ($c -eq 0x30) {
            $this.I++
        } elseif ($c -ge 0x31 -and $c -le 0x39) {
            while ($this.IsDigit($this.Peek())) { $this.I++ }
        } else {
            $this.Fail('json-syntax', $null)   # "-" alone, or "-Infinity"
        }
        $isInteger = $true
        if ($this.Peek() -eq 0x2E -and $this.I + 1 -lt $this.S.Length -and
            $this.IsDigit([int]$this.S[$this.I + 1])) {
            $isInteger = $false
            $this.I++
            while ($this.IsDigit($this.Peek())) { $this.I++ }
        }
        $c = $this.Peek()
        if ($c -eq 0x65 -or $c -eq 0x45) {
            $j = $this.I + 1
            if ($j -lt $this.S.Length -and ([int]$this.S[$j] -eq 0x2B -or [int]$this.S[$j] -eq 0x2D)) { $j++ }
            if ($j -lt $this.S.Length -and $this.IsDigit([int]$this.S[$j])) {
                $isInteger = $false
                $this.I = $j
                while ($this.IsDigit($this.Peek())) { $this.I++ }
            }
        }
        # Anything left over (e.g. "1." or "01") is rejected by the caller.
        return [JsonNumber]::new($this.S.Substring($start, $this.I - $start), $isInteger)
    }

    [int] HexValue([int]$c) {
        if ($c -ge 0x30 -and $c -le 0x39) { return $c - 0x30 }
        if ($c -ge 0x61 -and $c -le 0x66) { return $c - 0x61 + 10 }
        if ($c -ge 0x41 -and $c -le 0x46) { return $c - 0x41 + 10 }
        return -1
    }

    [string] ParseString() {
        $this.I++   # opening quote
        $builder = [System.Text.StringBuilder]::new()
        while ($true) {
            if ($this.I -ge $this.S.Length) { $this.Fail('json-syntax', $null) }
            $c = [int]$this.S[$this.I]
            if ($c -eq 0x22) { $this.I++; break }
            if ($c -lt 0x20) { $this.Fail('json-syntax', $null) }   # raw control character
            if ($c -ne 0x5C) { [void]$builder.Append($this.S[$this.I]); $this.I++; continue }
            $this.I++
            if ($this.I -ge $this.S.Length) { $this.Fail('json-syntax', $null) }
            $e = [int]$this.S[$this.I]
            $this.I++
            if ($e -eq 0x22) { [void]$builder.Append([char]0x22) }
            elseif ($e -eq 0x5C) { [void]$builder.Append([char]0x5C) }
            elseif ($e -eq 0x2F) { [void]$builder.Append([char]0x2F) }
            elseif ($e -eq 0x62) { [void]$builder.Append([char]0x08) }
            elseif ($e -eq 0x66) { [void]$builder.Append([char]0x0C) }
            elseif ($e -eq 0x6E) { [void]$builder.Append([char]0x0A) }
            elseif ($e -eq 0x72) { [void]$builder.Append([char]0x0D) }
            elseif ($e -eq 0x74) { [void]$builder.Append([char]0x09) }
            elseif ($e -eq 0x75) {
                if ($this.I + 4 -gt $this.S.Length) { $this.Fail('json-syntax', $null) }
                $value = 0
                for ($k = 0; $k -lt 4; $k++) {
                    $h = $this.HexValue([int]$this.S[$this.I + $k])
                    if ($h -lt 0) { $this.Fail('json-syntax', $null) }
                    $value = $value * 16 + $h
                }
                $this.I += 4
                # A surrogate pair written as two escapes simply becomes two UTF-16
                # units here; a lone surrogate stays lone and validation rejects it.
                [void]$builder.Append([char]$value)
            }
            else { $this.Fail('json-syntax', $null) }
        }
        return $builder.ToString()
    }

    [object] ParseObject() {
        $this.I++   # {
        $keys = [System.Collections.Generic.List[string]]::new()
        $values = [System.Collections.Generic.List[object]]::new()
        $this.SkipWs()
        if ($this.Peek() -eq 0x7D) {
            $this.I++
        } else {
            while ($true) {
                if ($this.Peek() -ne 0x22) { $this.Fail('json-syntax', $null) }
                $key = $this.ParseString()
                $this.SkipWs()
                if ($this.Peek() -ne 0x3A) { $this.Fail('json-syntax', $null) }
                $this.I++
                $this.SkipWs()
                $value = $this.ParseValue()
                $keys.Add($key)
                $values.Add($value)
                $this.SkipWs()
                $c = $this.Peek()
                if ($c -eq 0x7D) { $this.I++; break }
                if ($c -ne 0x2C) { $this.Fail('json-syntax', $null) }
                $this.I++
                $this.SkipWs()
            }
        }
        # Checked only now that the object has closed, exactly when Python's
        # object_pairs_hook runs, so an earlier syntax error wins on both sides.
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $result = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        for ($k = 0; $k -lt $keys.Count; $k++) {
            if (-not $seen.Add($keys[$k])) { $this.Fail('duplicate-key', $keys[$k]) }
            $result.Add($keys[$k], $values[$k])
        }
        return $result
    }

    [object] ParseArray() {
        $this.I++   # [
        $items = [System.Collections.Generic.List[object]]::new()
        $this.SkipWs()
        if ($this.Peek() -eq 0x5D) { $this.I++; return $items }
        while ($true) {
            $items.Add($this.ParseValue())
            $this.SkipWs()
            $c = $this.Peek()
            if ($c -eq 0x5D) { $this.I++; break }
            if ($c -ne 0x2C) { $this.Fail('json-syntax', $null) }
            $this.I++
            $this.SkipWs()
        }
        return $items
    }

    # Decision D21: brackets outside strings nesting deeper than 64 levels.
    static [bool] DepthExceeds([string]$text, [int]$limit) {
        $depth = 0
        $inString = $false
        $escaped = $false
        foreach ($ch in $text.ToCharArray()) {
            $c = [int]$ch
            if ($inString) {
                if ($escaped) { $escaped = $false }
                elseif ($c -eq 0x5C) { $escaped = $true }
                elseif ($c -eq 0x22) { $inString = $false }
                continue
            }
            if ($c -eq 0x22) { $inString = $true }
            elseif ($c -eq 0x5B -or $c -eq 0x7B) {
                $depth++
                if ($depth -gt $limit) { return $true }
            }
            elseif ($c -eq 0x5D -or $c -eq 0x7D) { $depth-- }
        }
        return $false
    }
}

# Serializers: D13 canonical form for stored lines, and an ASCII-only form for
# validate-* output (the console's code page can't be trusted with non-ASCII).
class JsonOut {
    static [string] Hex4([int]$c) { return ([string]::Format('\u{0:x4}', $c)) }

    static [void] WriteString([System.Text.StringBuilder]$b, [string]$s, [bool]$ascii) {
        [void]$b.Append([char]0x22)
        foreach ($ch in $s.ToCharArray()) {
            $c = [int]$ch
            if ($c -eq 0x22) { [void]$b.Append('\"') }
            elseif ($c -eq 0x5C) { [void]$b.Append('\\') }
            elseif ($c -eq 0x0A) { [void]$b.Append('\n') }
            elseif ($c -eq 0x0D) { [void]$b.Append('\r') }
            elseif ($c -eq 0x09) { [void]$b.Append('\t') }
            elseif ($c -eq 0x08) { [void]$b.Append('\b') }
            elseif ($c -eq 0x0C) { [void]$b.Append('\f') }
            elseif ($c -lt 0x20 -or $c -eq 0x2028 -or $c -eq 0x2029) { [void]$b.Append([JsonOut]::Hex4($c)) }
            elseif ($ascii -and $c -gt 0x7E) { [void]$b.Append([JsonOut]::Hex4($c)) }
            else { [void]$b.Append($ch) }
        }
        [void]$b.Append([char]0x22)
    }

    static [void] Write([System.Text.StringBuilder]$b, [object]$v, [bool]$ascii) {
        if ($null -eq $v) { [void]$b.Append('null'); return }
        if ($v -is [string]) { [JsonOut]::WriteString($b, $v, $ascii); return }
        if ($v -is [bool]) { if ($v) { [void]$b.Append('true') } else { [void]$b.Append('false') }; return }
        if ($v -is [JsonNumber]) { [void]$b.Append($v.Text); return }
        if ($v -is [int] -or $v -is [long]) {
            [void]$b.Append($v.ToString([System.Globalization.CultureInfo]::InvariantCulture)); return
        }
        if ($v -is [System.Collections.IDictionary]) {
            [void]$b.Append('{')
            $first = $true
            foreach ($key in $v.Keys) {
                if (-not $first) { [void]$b.Append(',') }
                $first = $false
                [JsonOut]::WriteString($b, [string]$key, $ascii)
                [void]$b.Append(':')
                [JsonOut]::Write($b, $v[$key], $ascii)
            }
            [void]$b.Append('}')
            return
        }
        if ($v -is [System.Collections.IEnumerable]) {
            [void]$b.Append('[')
            $first = $true
            foreach ($item in $v) {
                if (-not $first) { [void]$b.Append(',') }
                $first = $false
                [JsonOut]::Write($b, $item, $ascii)
            }
            [void]$b.Append(']')
            return
        }
        throw [System.ArgumentException]::new('cannot serialize ' + $v.GetType().FullName)
    }

    static [string] Canonical([object]$v) {
        $b = [System.Text.StringBuilder]::new()
        [JsonOut]::Write($b, $v, $false)
        return $b.ToString()
    }

    static [string] Ascii([object]$v) {
        $b = [System.Text.StringBuilder]::new()
        [JsonOut]::Write($b, $v, $true)
        return $b.ToString()
    }
}

# ==========================================================================
# Validation (mirrors exception_grants.py, same order, same codes)
# ==========================================================================

class VError {
    [string]$Code
    [object]$Field
    [object]$Line
    VError([string]$code, [object]$field) { $this.Code = $code; $this.Field = $field; $this.Line = $null }

    [string] Describe() {
        $text = $this.Code
        if ($null -ne $this.Field) { $text += " in '" + $this.Field + "'" }
        if ($null -ne $this.Line) { $text = 'line ' + $this.Line + ': ' + $text }
        return $text
    }
}

# One parsed grants file, or the reason it is invalid.
class GrantsFileResult {
    [VError]$Error
    [System.Collections.Generic.List[object]]$Records   # OrderedDictionary per line
}

class Rules {
    static [int] $MaxFileBytes = 1048576
    static [string[]] $KnownHosts = @('claude', 'codex', 'cursor', 'windsurf', 'devin', 'antigravity')
    static [regex] $NameRe = [regex]::new('\A[a-z0-9][a-z0-9-]{0,39}\z')
    static [regex] $DurationRe = [regex]::new('\A([1-9][0-9]{0,3})([mhd])\z')
    static [regex] $RequestTsRe = [regex]::new('\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(Z|([+-])([0-9]{2}):([0-9]{2}))\z')
    static [regex] $StoredTsRe = [regex]::new('\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\z')
    static [regex] $SidRe = [regex]::new('\AS-1-(0|[1-9][0-9]{0,14})((-(0|[1-9][0-9]{0,9})){1,15})\z')
    static [regex] $GrantIdRe = [regex]::new('\Ag-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\z')
    static [regex] $RevokeIdRe = [regex]::new('\Ar-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\z')
    static [regex] $DrivePathRe = [regex]::new('\A[A-Za-z]:[\\/]')
    static [string[]] $RequestFields = @('v', 'name', 'commands', 'tool', 'where', 'cwd', 'hosts', 'expires', 'why')
    static [string[]] $RequestRequired = @('v', 'name', 'commands', 'tool', 'where', 'hosts', 'expires', 'why')
    static [string[]] $GrantFields = @('v', 'type', 'id', 'name', 'ts', 'user', 'user_display', 'commands', 'tool', 'where', 'path', 'hosts', 'expires', 'why')
    static [string[]] $RevokeFields = @('v', 'type', 'id', 'ts', 'user', 'name')
    # Python's str.isspace() set, spelled out (decision D23).
    static [string] $WhitespaceChars = "`t`n`v`f`r" + [string][char]0x1C + [char]0x1D + [char]0x1E + [char]0x1F +
        ' ' + [char]0x85 + [char]0xA0 + [char]0x1680 + [char]0x2000 + [char]0x2001 + [char]0x2002 +
        [char]0x2003 + [char]0x2004 + [char]0x2005 + [char]0x2006 + [char]0x2007 + [char]0x2008 +
        [char]0x2009 + [char]0x200A + [char]0x2028 + [char]0x2029 + [char]0x202F + [char]0x205F + [char]0x3000

    static [bool] Same([object]$a, [string]$b) {
        return ($a -is [string]) -and [string]::Equals([string]$a, $b, [System.StringComparison]::Ordinal)
    }

    static [bool] IsDict([object]$v) { return $v -is [System.Collections.Specialized.OrderedDictionary] }
    static [bool] IsList([object]$v) { return $v -is [System.Collections.Generic.List[object]] }

    # Unicode code points, with a surrogate pair counted once (decision D18).
    static [int] CodePoints([string]$s) {
        $count = 0
        for ($i = 0; $i -lt $s.Length; $i++) {
            if ([char]::IsHighSurrogate($s[$i]) -and $i + 1 -lt $s.Length -and [char]::IsLowSurrogate($s[$i + 1])) { $i++ }
            $count++
        }
        return $count
    }

    static [bool] HasLoneSurrogate([string]$s) {
        for ($i = 0; $i -lt $s.Length; $i++) {
            if ([char]::IsHighSurrogate($s[$i])) {
                if ($i + 1 -lt $s.Length -and [char]::IsLowSurrogate($s[$i + 1])) { $i++; continue }
                return $true
            }
            if ([char]::IsLowSurrogate($s[$i])) { return $true }
        }
        return $false
    }

    static [bool] IsKnownHost([string]$h) {
        foreach ($known in [Rules]::KnownHosts) {
            if ([string]::Equals($h, $known, [System.StringComparison]::Ordinal)) { return $true }
        }
        return $false
    }

    # Returns the UTC ticks of a request or stored timestamp, or -1 if invalid.
    static [long] TimestampTicks([string]$text, [bool]$stored) {
        $re = [Rules]::RequestTsRe
        if ($stored) { $re = [Rules]::StoredTsRe }
        $m = $re.Match($text)
        if (-not $m.Success) { return -1 }
        $offsetTicks = [long]0
        if (-not $stored -and $m.Groups[7].Value -cne 'Z') {
            $hours = [int]$m.Groups[9].Value
            $minutes = [int]$m.Groups[10].Value
            if ($hours -gt 23 -or $minutes -gt 59) { return -1 }
            $offsetTicks = ([long]$hours * 60 + $minutes) * [TimeSpan]::TicksPerMinute
            if ($m.Groups[8].Value -ceq '-') { $offsetTicks = -$offsetTicks }
        }
        try {
            $local = [DateTime]::new([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value,
                                     [int]$m.Groups[4].Value, [int]$m.Groups[5].Value, [int]$m.Groups[6].Value,
                                     [DateTimeKind]::Unspecified)
        } catch {
            return -1
        }
        return $local.Ticks - $offsetTicks
    }

    # Decision D19: regex plus numeric limits.
    static [bool] IsValidSid([string]$text) {
        $m = [Rules]::SidRe.Match($text)
        if (-not $m.Success) { return $false }
        if ([UInt64]::Parse($m.Groups[1].Value) -gt [UInt64]281474976710655) { return $false }
        foreach ($part in $m.Groups[2].Value.Substring(1).Split('-')) {
            if ([UInt64]::Parse($part) -gt [UInt64]4294967295) { return $false }
        }
        return $true
    }

    static [VError] PathError([object]$value, [string]$field) {
        if (-not ($value -is [string])) { return [VError]::new('bad-type', $field) }
        if (-not [Rules]::DrivePathRe.IsMatch($value) -or [Rules]::HasLoneSurrogate($value)) {
            return [VError]::new('bad-value', $field)
        }
        foreach ($part in ([string]$value).Split([char[]]@([char]0x5C, [char]0x2F))) {
            if ($part -ceq '.' -or $part -ceq '..') { return [VError]::new('bad-value', $field) }
        }
        return $null
    }

    static [VError] VErr([object]$value) {
        if ($value -is [JsonNumber] -and $value.IsInteger) {
            if ($value.Text -ceq '1') { return $null }
            return [VError]::new('bad-value', 'v')
        }
        return [VError]::new('bad-type', 'v')
    }

    static [VError] NameErr([object]$value, [bool]$allowStar) {
        if (-not ($value -is [string])) { return [VError]::new('bad-type', 'name') }
        if ($allowStar -and $value -ceq '*') { return $null }
        if (-not [Rules]::NameRe.IsMatch($value)) { return [VError]::new('bad-value', 'name') }
        return $null
    }

    static [VError] CommandsErr([object]$value) {
        if (-not [Rules]::IsList($value)) { return [VError]::new('bad-type', 'commands') }
        if ($value.Count -lt 1 -or $value.Count -gt 20) { return [VError]::new('bad-value', 'commands') }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($item in $value) {
            if (-not ($item -is [string])) { return [VError]::new('bad-type', 'commands') }
            $length = [Rules]::CodePoints($item)
            if ($length -lt 1 -or $length -gt 8000) { return [VError]::new('bad-value', 'commands') }
            if ($item.IndexOf([char]0) -ge 0) { return [VError]::new('bad-value', 'commands') }
            $allSpace = $true
            foreach ($ch in $item.ToCharArray()) {
                if ([Rules]::WhitespaceChars.IndexOf($ch) -lt 0) { $allSpace = $false; break }
            }
            if ($allSpace) { return [VError]::new('bad-value', 'commands') }
            if ([Rules]::HasLoneSurrogate($item)) { return [VError]::new('bad-value', 'commands') }
            if (-not $seen.Add($item)) { return [VError]::new('bad-value', 'commands') }
        }
        return $null
    }

    static [VError] TextErr([object]$value, [string]$field, [int]$low, [int]$high) {
        if (-not ($value -is [string])) { return [VError]::new('bad-type', $field) }
        $length = [Rules]::CodePoints($value)
        if ($length -lt $low -or $length -gt $high) { return [VError]::new('bad-value', $field) }
        if ([Rules]::HasLoneSurrogate($value)) { return [VError]::new('bad-value', $field) }
        return $null
    }

    static [VError] WhereErr([object]$value) {
        if (-not ($value -is [string])) { return [VError]::new('bad-type', 'where') }
        if ($value -cne 'dir' -and $value -cne 'repo' -and $value -cne 'any') { return [VError]::new('bad-value', 'where') }
        return $null
    }

    static [VError] HostsErr([object]$value) {
        if ($null -eq $value) { return $null }
        if (-not [Rules]::IsList($value)) { return [VError]::new('bad-type', 'hosts') }
        if ($value.Count -eq 0) { return [VError]::new('bad-value', 'hosts') }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($item in $value) {
            if (-not ($item -is [string])) { return [VError]::new('bad-type', 'hosts') }
            if (-not [Rules]::IsKnownHost($item) -or -not $seen.Add($item)) { return [VError]::new('bad-value', 'hosts') }
        }
        return $null
    }

    static [VError] SchemaErr([System.Collections.Specialized.OrderedDictionary]$obj, [string[]]$allowed, [string[]]$required) {
        $allowedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$allowed, [System.StringComparer]::Ordinal)
        foreach ($key in $obj.Keys) {
            if (-not $allowedSet.Contains([string]$key)) { return [VError]::new('unknown-field', [string]$key) }
        }
        foreach ($key in $required) {
            if (-not $obj.Contains($key)) { return [VError]::new('missing-field', $key) }
        }
        return $null
    }

    # Text validation of a request block (Python validate_request).
    static [VError] Request([object]$obj, [long]$nowTicks) {
        if (-not [Rules]::IsDict($obj)) { return [VError]::new('not-object', $null) }
        $e = [Rules]::SchemaErr($obj, [Rules]::RequestFields, [Rules]::RequestRequired)
        if ($null -ne $e) { return $e }
        $e = [Rules]::VErr($obj['v']); if ($null -ne $e) { return $e }
        $e = [Rules]::NameErr($obj['name'], $false); if ($null -ne $e) { return $e }
        $e = [Rules]::CommandsErr($obj['commands']); if ($null -ne $e) { return $e }
        $e = [Rules]::TextErr($obj['tool'], 'tool', 0, 40); if ($null -ne $e) { return $e }
        $e = [Rules]::WhereErr($obj['where']); if ($null -ne $e) { return $e }
        if ($obj['where'] -ceq 'any') {
            if ($null -ne $obj['cwd']) { return [VError]::new('bad-value', 'cwd') }
        } elseif (-not $obj.Contains('cwd')) {
            return [VError]::new('missing-field', 'cwd')
        } else {
            $e = [Rules]::PathError($obj['cwd'], 'cwd'); if ($null -ne $e) { return $e }
        }
        $e = [Rules]::HostsErr($obj['hosts']); if ($null -ne $e) { return $e }
        $expires = $obj['expires']
        if (-not ($expires -is [string])) { return [VError]::new('bad-type', 'expires') }
        if ($expires -cne 'never' -and -not [Rules]::DurationRe.IsMatch($expires)) {
            $ticks = [Rules]::TimestampTicks($expires, $false)
            if ($ticks -lt 0) { return [VError]::new('bad-value', 'expires') }
            if ($ticks -le $nowTicks) { return [VError]::new('expired', 'expires') }
        }
        $e = [Rules]::TextErr($obj['why'], 'why', 0, 1000); if ($null -ne $e) { return $e }
        return $null
    }

    static [VError] IdErr([object]$value, [regex]$pattern) {
        if (-not ($value -is [string])) { return [VError]::new('bad-type', 'id') }
        if (-not $pattern.IsMatch($value)) { return [VError]::new('bad-value', 'id') }
        return $null
    }

    static [VError] StoredTsErr([object]$value, [string]$field, [bool]$nullable) {
        if ($null -eq $value -and $nullable) { return $null }
        if (-not ($value -is [string])) { return [VError]::new('bad-type', $field) }
        if ([Rules]::TimestampTicks($value, $true) -lt 0) { return [VError]::new('bad-value', $field) }
        return $null
    }

    static [VError] UserErr([object]$value) {
        if (-not ($value -is [string])) { return [VError]::new('bad-type', 'user') }
        if (-not [Rules]::IsValidSid($value)) { return [VError]::new('bad-value', 'user') }
        return $null
    }

    # Stored record validation (Python validate_record).
    static [VError] Record([object]$obj) {
        if (-not [Rules]::IsDict($obj)) { return [VError]::new('not-object', $null) }
        if (-not $obj.Contains('type')) { return [VError]::new('missing-field', 'type') }
        if ([Rules]::Same($obj['type'], 'grant')) { return [Rules]::GrantRecord($obj) }
        if ([Rules]::Same($obj['type'], 'revoke')) { return [Rules]::RevokeRecord($obj) }
        return [VError]::new('bad-value', 'type')
    }

    static [VError] GrantRecord([System.Collections.Specialized.OrderedDictionary]$obj) {
        $e = [Rules]::SchemaErr($obj, [Rules]::GrantFields, [Rules]::GrantFields); if ($null -ne $e) { return $e }
        $e = [Rules]::VErr($obj['v']); if ($null -ne $e) { return $e }
        $e = [Rules]::IdErr($obj['id'], [Rules]::GrantIdRe); if ($null -ne $e) { return $e }
        $e = [Rules]::NameErr($obj['name'], $false); if ($null -ne $e) { return $e }
        $e = [Rules]::StoredTsErr($obj['ts'], 'ts', $false); if ($null -ne $e) { return $e }
        $e = [Rules]::UserErr($obj['user']); if ($null -ne $e) { return $e }
        $e = [Rules]::TextErr($obj['user_display'], 'user_display', 1, 256); if ($null -ne $e) { return $e }
        $e = [Rules]::CommandsErr($obj['commands']); if ($null -ne $e) { return $e }
        $e = [Rules]::TextErr($obj['tool'], 'tool', 0, 40); if ($null -ne $e) { return $e }
        $e = [Rules]::WhereErr($obj['where']); if ($null -ne $e) { return $e }
        if ($obj['where'] -ceq 'any') {
            if ($null -ne $obj['path']) { return [VError]::new('bad-value', 'path') }
        } elseif ($null -eq $obj['path']) {
            return [VError]::new('bad-value', 'path')
        } else {
            $e = [Rules]::PathError($obj['path'], 'path'); if ($null -ne $e) { return $e }
        }
        $e = [Rules]::HostsErr($obj['hosts']); if ($null -ne $e) { return $e }
        $e = [Rules]::StoredTsErr($obj['expires'], 'expires', $true); if ($null -ne $e) { return $e }
        $e = [Rules]::TextErr($obj['why'], 'why', 0, 1000); if ($null -ne $e) { return $e }
        return $null
    }

    static [VError] RevokeRecord([System.Collections.Specialized.OrderedDictionary]$obj) {
        $e = [Rules]::SchemaErr($obj, [Rules]::RevokeFields, [Rules]::RevokeFields); if ($null -ne $e) { return $e }
        $e = [Rules]::VErr($obj['v']); if ($null -ne $e) { return $e }
        $e = [Rules]::IdErr($obj['id'], [Rules]::RevokeIdRe); if ($null -ne $e) { return $e }
        $e = [Rules]::StoredTsErr($obj['ts'], 'ts', $false); if ($null -ne $e) { return $e }
        $e = [Rules]::UserErr($obj['user']); if ($null -ne $e) { return $e }
        $e = [Rules]::NameErr($obj['name'], $true); if ($null -ne $e) { return $e }
        return $null
    }

    # Parse one JSON line (Python parse_json_line). Sets $parsed on success.
    static [VError] ParseLine([string]$text, [ref]$parsed) {
        if ([JsonParser]::DepthExceeds($text, 64)) { return [VError]::new('json-syntax', $null) }
        $parser = [JsonParser]::new($text)
        try {
            $parsed.Value = $parser.ParseDocument()
        } catch [System.FormatException] {
            return [VError]::new($parser.Code, $parser.Field)
        }
        return $null
    }

    # Decode and text-validate request bytes (Python parse_request_bytes).
    static [VError] RequestBytes([byte[]]$data, [long]$nowTicks, [ref]$parsed) {
        if ($data.Length -ge 3 -and $data[0] -eq 0xEF -and $data[1] -eq 0xBB -and $data[2] -eq 0xBF) {
            return [VError]::new('bom', $null)
        }
        try {
            $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($data)
        } catch {
            return [VError]::new('encoding', $null)
        }
        $e = [Rules]::ParseLine($text, $parsed)
        if ($null -ne $e) { return $e }
        return [Rules]::Request($parsed.Value, $nowTicks)
    }

    static [GrantsFileResult] Fail([string]$code, [object]$field, [object]$line) {
        $r = [GrantsFileResult]::new()
        $r.Error = [VError]::new($code, $field)
        $r.Error.Line = $line
        return $r
    }

    # Whole-file validation (Python validate_file_bytes).
    static [GrantsFileResult] File([byte[]]$data) {
        if ($data.Length -gt [Rules]::MaxFileBytes) { return [Rules]::Fail('too-large', $null, $null) }
        if ($data.Length -ge 3 -and $data[0] -eq 0xEF -and $data[1] -eq 0xBB -and $data[2] -eq 0xBF) {
            return [Rules]::Fail('bom', $null, $null)
        }
        try {
            $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($data)
        } catch {
            return [Rules]::Fail('encoding', $null, $null)
        }
        if ($text.IndexOf([char]0x0D) -ge 0) { return [Rules]::Fail('cr', $null, $null) }
        $result = [GrantsFileResult]::new()
        $result.Records = [System.Collections.Generic.List[object]]::new()
        if ($text.Length -eq 0) { return $result }
        if ($text[$text.Length - 1] -ne [char]0x0A) { return [Rules]::Fail('no-final-newline', $null, $null) }
        $lines = $text.Substring(0, $text.Length - 1).Split([char]0x0A)
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        for ($n = 0; $n -lt $lines.Length; $n++) {
            $number = $n + 1
            if ($lines[$n].Length -eq 0) { return [Rules]::Fail('blank-line', $null, $number) }
            $parsed = $null
            $e = [Rules]::ParseLine($lines[$n], [ref]$parsed)
            if ($null -eq $e) { $e = [Rules]::Record($parsed) }
            if ($null -ne $e) { return [Rules]::Fail($e.Code, $e.Field, $number) }
            if (-not $seen.Add([string]$parsed['id'])) { return [Rules]::Fail('duplicate-id', 'id', $number) }
            $result.Records.Add($parsed)
        }
        return $result
    }

    # Active grants in file order (Python active_grants).
    static [System.Collections.Generic.List[object]] Active([System.Collections.Generic.List[object]]$records, [long]$nowTicks) {
        $active = [System.Collections.Generic.List[object]]::new()
        foreach ($record in $records) {
            if ($record['type'] -ceq 'grant') { $active.Add($record); continue }
            $kept = [System.Collections.Generic.List[object]]::new()
            foreach ($grant in $active) {
                $sameUser = [string]::Equals($grant['user'], $record['user'], [System.StringComparison]::Ordinal)
                $named = ($record['name'] -ceq '*') -or [string]::Equals($grant['name'], $record['name'], [System.StringComparison]::Ordinal)
                if (-not ($sameUser -and $named)) { $kept.Add($grant) }
            }
            $active = $kept
        }
        $live = [System.Collections.Generic.List[object]]::new()
        foreach ($grant in $active) {
            if ($null -eq $grant['expires'] -or $nowTicks -lt [Rules]::TimestampTicks($grant['expires'], $true)) {
                $live.Add($grant)
            }
        }
        return $live
    }
}

# ==========================================================================
# Display helpers
# ==========================================================================

class Visible {
    # Make invisible characters visible for the confirmation dialog.
    static [string] Format([string]$s) {
        $b = [System.Text.StringBuilder]::new()
        $chars = $s.ToCharArray()
        $lead = 0
        while ($lead -lt $chars.Length -and [int]$chars[$lead] -eq 0x20) { $lead++ }
        $trail = $chars.Length
        while ($trail -gt $lead -and [int]$chars[$trail - 1] -eq 0x20) { $trail-- }
        for ($i = 0; $i -lt $chars.Length; $i++) {
            $c = [int]$chars[$i]
            if ($c -eq 0x20 -and ($i -lt $lead -or $i -ge $trail)) { [void]$b.Append([char]0x00B7); continue }
            if ($c -eq 0x09) { [void]$b.Append([char]0x21E5); continue }
            if ($c -eq 0x0D) { [void]$b.Append([char]0x240D); continue }
            if ($c -eq 0x0A) { [void]$b.Append([char]0x240A); [void]$b.Append([char]0x0A); continue }
            if ($c -lt 0x20) { [void]$b.Append([char](0x2400 + $c)); continue }
            if ($c -eq 0x7F) { [void]$b.Append([char]0x2421); continue }
            if (($c -ge 0x200B -and $c -le 0x200F) -or ($c -ge 0x202A -and $c -le 0x202E) -or
                ($c -ge 0x2060 -and $c -le 0x2069) -or $c -eq 0xFEFF) {
                [void]$b.Append([string]::Format('{0}U+{1:X4}{2}', [char]0x27E6, $c, [char]0x27E7))
                continue
            }
            [void]$b.Append($chars[$i])
        }
        return $b.ToString()
    }
}

# A line diff for repair edits (decision D20).
class LineDiff {
    [string]$Path                                     # "lcs" or "fallback"
    [System.Collections.Generic.List[string]]$Lines   # "  x", "- x", "+ x"

    static [LineDiff] Compute([string[]]$old, [string[]]$new) {
        $diff = [LineDiff]::new()
        $diff.Lines = [System.Collections.Generic.List[string]]::new()
        $n = $old.Length
        $m = $new.Length
        # [long] so the product can't overflow before the comparison.
        if ([long]$n * [long]$m -gt [long]1000000) {
            $diff.Path = 'fallback'
            foreach ($line in $old) { $diff.Lines.Add('- ' + $line) }
            foreach ($line in $new) { $diff.Lines.Add('+ ' + $line) }
            return $diff
        }
        $diff.Path = 'lcs'
        $width = $m + 1
        # table[i * width + j] = LCS length of old[i..] and new[j..]
        $table = [int[]]::new(($n + 1) * $width)
        for ($i = $n - 1; $i -ge 0; $i--) {
            for ($j = $m - 1; $j -ge 0; $j--) {
                if ([string]::Equals($old[$i], $new[$j], [System.StringComparison]::Ordinal)) {
                    $table[$i * $width + $j] = $table[($i + 1) * $width + $j + 1] + 1
                } else {
                    $down = $table[($i + 1) * $width + $j]
                    $right = $table[$i * $width + $j + 1]
                    if ($down -ge $right) { $table[$i * $width + $j] = $down } else { $table[$i * $width + $j] = $right }
                }
            }
        }
        $i = 0
        $j = 0
        while ($i -lt $n -and $j -lt $m) {
            if ([string]::Equals($old[$i], $new[$j], [System.StringComparison]::Ordinal)) {
                $diff.Lines.Add('  ' + $old[$i]); $i++; $j++
            } elseif ($table[($i + 1) * $width + $j] -ge $table[$i * $width + $j + 1]) {
                $diff.Lines.Add('- ' + $old[$i]); $i++
            } else {
                $diff.Lines.Add('+ ' + $new[$j]); $j++
            }
        }
        while ($i -lt $n) { $diff.Lines.Add('- ' + $old[$i]); $i++ }
        while ($j -lt $m) { $diff.Lines.Add('+ ' + $new[$j]); $j++ }
        return $diff
    }
}

# ==========================================================================
# Integrity rule (I4/I5), on raw security descriptors
# ==========================================================================

class Security {
    static [string[]] $Trusted = @('S-1-5-32-544', 'S-1-5-18',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    static [int] $WriteMask = 0x500D0156
    static [int] $AncestorMask = 0x100D0040

    static [bool] IsTrusted([string]$sid) {
        foreach ($t in [Security]::Trusted) { if ($sid -ceq $t) { return $true } }
        return $false
    }

    # Returns problems as [code, message] pairs, in the shared order (I4a).
    static [System.Collections.Generic.List[string[]]] Evaluate([byte[]]$sd, [bool]$isReparse, [string]$role, [string]$label) {
        $problems = [System.Collections.Generic.List[string[]]]::new()
        try {
            $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($sd, 0)
        } catch {
            $problems.Add([string[]]@('malformed', "could not parse the security of $label"))
            return $problems
        }
        $owner = $null
        if ($null -ne $raw.Owner) { $owner = $raw.Owner.Value }
        if ($null -eq $owner -or -not [Security]::IsTrusted($owner)) {
            $problems.Add([string[]]@('owner', "$label is owned by $owner, not an administrator"))
        }
        if ($isReparse) { $problems.Add([string[]]@('reparse', "$label is a symlink or junction")) }
        $present = ($raw.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0
        if (-not $present -or $null -eq $raw.DiscretionaryAcl) {
            $problems.Add([string[]]@('null-dacl', "$label has no permission list (everyone may write)"))
            return $problems
        }
        foreach ($ace in $raw.DiscretionaryAcl) {
            $type = [int]$ace.AceType
            if ($type -ne 0 -and $type -ne 1) {
                $problems.Add([string[]]@('ace-type', "$label has an unusual permission entry (type $type)"))
                break
            }
        }
        $mask = [Security]::WriteMask
        if ($role -ceq 'ancestor') { $mask = [Security]::AncestorMask }
        foreach ($ace in $raw.DiscretionaryAcl) {
            if ([int]$ace.AceType -ne 0) { continue }
            if (([int]$ace.AceFlags -band 0x08) -ne 0) { continue }   # inherit-only
            $sid = $ace.SecurityIdentifier.Value
            if ([Security]::IsTrusted($sid)) { continue }
            if (($ace.AccessMask -band $mask) -ne 0) {
                $problems.Add([string[]]@('write-right', "$sid can change $label"))
                break
            }
        }
        if ($role -ceq 'folder' -and
            ($raw.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
            $problems.Add([string[]]@('not-protected', "$label inherits permissions from its parent"))
        }
        return $problems
    }
}

# ==========================================================================
# Functions: filesystem, conversion, description
# ==========================================================================

function Get-DescriptorBytes([string]$path, [bool]$isFolder) {
    $sections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
    if ($isFolder) { $security = [System.IO.Directory]::GetAccessControl($path, $sections) }
    else { $security = [System.IO.File]::GetAccessControl($path, $sections) }
    return ,$security.GetSecurityDescriptorBinaryForm()
}

function Test-IsReparse([string]$path) {
    $attributes = [System.IO.File]::GetAttributes($path)
    return ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
}

# The administrative integrity check (design 4.1): the folder, the grants file,
# optionally the writer itself, and every parent folder. Returns messages.
function Test-StoreIntegrity([string]$grantsPath, [string]$writerPath) {
    $messages = [System.Collections.Generic.List[string]]::new()
    $folder = [System.IO.Path]::GetDirectoryName($grantsPath)
    if (-not [System.IO.Directory]::Exists($folder) -or -not [System.IO.File]::Exists($grantsPath)) {
        $messages.Add('Exception grants are not set up. Run: aiallow setup')
        return ,$messages
    }
    $targets = [System.Collections.Generic.List[string[]]]::new()
    $targets.Add([string[]]@($folder, 'folder'))
    $targets.Add([string[]]@($grantsPath, 'file'))
    if ($writerPath) { $targets.Add([string[]]@($writerPath, 'file')) }
    $parent = [System.IO.Directory]::GetParent($folder)
    while ($null -ne $parent) {
        $targets.Add([string[]]@($parent.FullName, 'ancestor'))
        $parent = $parent.Parent
    }
    foreach ($target in $targets) {
        try {
            $bytes = Get-DescriptorBytes $target[0] ($target[1] -cne 'file')
            $problems = [Security]::Evaluate($bytes, (Test-IsReparse $target[0]), $target[1], $target[0])
            foreach ($problem in $problems) { $messages.Add($problem[1]) }
        } catch {
            $messages.Add('could not read security of ' + $target[0] + ': ' + $_.Exception.Message)
        }
    }
    return ,$messages
}

function Get-RepoRoot([string]$cwd) {
    $dir = [System.IO.DirectoryInfo]::new($cwd)
    while ($null -ne $dir) {
        $marker = [System.IO.Path]::Combine($dir.FullName, '.git')
        if ([System.IO.Directory]::Exists($marker) -or [System.IO.File]::Exists($marker)) { return $dir.FullName }
        $dir = $dir.Parent
    }
    return $null
}

function Format-StoredTime([DateTime]$utc) {
    return $utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-UtcNow([string]$override) {
    if ($override) {
        $ticks = [Rules]::TimestampTicks($override, $true)
        if ($ticks -lt 0) { throw [System.ArgumentException]::new('-Now must be yyyy-MM-ddTHH:mm:ssZ') }
        return [DateTime]::new($ticks, [DateTimeKind]::Utc)
    }
    $now = [DateTime]::UtcNow
    # Whole seconds, so ts and expiry are exact in the stored form.
    return [DateTime]::new($now.Ticks - ($now.Ticks % [TimeSpan]::TicksPerSecond), [DateTimeKind]::Utc)
}

function New-RecordId([string]$prefix, [DateTime]$now, $existingIds) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        while ($true) {
            $bytes = [byte[]]::new(4)
            $rng.GetBytes($bytes)
            $hex = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
            $id = $prefix + $now.ToString("yyyyMMdd'T'HHmmss'Z'", [System.Globalization.CultureInfo]::InvariantCulture) + '-' + $hex
            if (-not $existingIds.Contains($id)) { return $id }
        }
    } finally {
        $rng.Dispose()
    }
}

function Get-UserDisplay([string]$sid) {
    try {
        $identifier = [System.Security.Principal.SecurityIdentifier]::new($sid)
        return $identifier.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $sid
    }
}

function New-Ordered {
    return ,[System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
}

function Get-IdSet($records) {
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    if ($null -ne $records) { foreach ($record in $records) { [void]$ids.Add([string]$record['id']) } }
    return ,$ids
}

# Convert a text-valid request into a stored grant record. Returns
# @{ Error = [VError] or $null; Record = OrderedDictionary or $null } as an
# ordinal OrderedDictionary.
function ConvertTo-Grant($request, [string]$forUser, [DateTime]$now, $records, [string]$expiresOverride) {
    $result = New-Ordered
    $result['Error'] = $null
    $result['Record'] = $null
    $where = [string]$request['where']
    $path = $null
    if ($where -cne 'any') {
        $cwd = ([string]$request['cwd']).Replace('/', '\')
        if ($cwd.Length -gt 3) { $cwd = $cwd.TrimEnd('\') }
        if (-not [System.IO.Directory]::Exists($cwd)) {
            $result['Error'] = [VError]::new('bad-value', 'cwd'); return ,$result
        }
        $path = $cwd
        if ($where -ceq 'repo') {
            $path = Get-RepoRoot $cwd
            if ($null -eq $path) { $result['Error'] = [VError]::new('bad-value', 'where'); return ,$result }
        }
    }
    $expires = [string]$request['expires']
    if ($expiresOverride) { $expires = $expiresOverride }
    $resolved = Resolve-Expiry $expires $now
    if ($null -ne $resolved['Error']) { $result['Error'] = $resolved['Error']; return ,$result }
    $expiresValue = $resolved['Value']
    $record = New-Ordered
    $record['v'] = [JsonNumber]::new('1', $true)
    $record['type'] = 'grant'
    $record['id'] = New-RecordId 'g-' $now (Get-IdSet $records)
    $record['name'] = $request['name']
    $record['ts'] = Format-StoredTime $now
    $record['user'] = $forUser
    $record['user_display'] = Get-UserDisplay $forUser
    $record['commands'] = $request['commands']
    $record['tool'] = $request['tool']
    $record['where'] = $where
    $record['path'] = $path
    $record['hosts'] = $request['hosts']
    $record['expires'] = $expiresValue
    $record['why'] = $request['why']
    $result['Record'] = $record
    return ,$result
}

# An expiry choice ("30m", "never", or an ISO time) as the stored UTC string,
# or $null for never. Returns an ordinal OrderedDictionary with Error and Value.
function Resolve-Expiry([string]$expires, [DateTime]$now) {
    $result = New-Ordered
    $result['Error'] = $null
    $result['Value'] = $null
    if ($expires -ceq 'never') { return ,$result }
    $m = [Rules]::DurationRe.Match($expires)
    try {
        if ($m.Success) {
            $count = [int]$m.Groups[1].Value
            $unit = $m.Groups[2].Value
            if ($unit -ceq 'm') { $moment = $now.AddMinutes($count) }
            elseif ($unit -ceq 'h') { $moment = $now.AddHours($count) }
            else { $moment = $now.AddDays($count) }
        } else {
            $ticks = [Rules]::TimestampTicks($expires, $false)
            if ($ticks -lt 0) { throw [System.ArgumentException]::new('bad expiry') }
            $moment = [DateTime]::new($ticks, [DateTimeKind]::Utc)
        }
    } catch {
        $result['Error'] = [VError]::new('bad-value', 'expires')
        return ,$result
    }
    $result['Value'] = Format-StoredTime $moment
    return ,$result
}

# A copy of an already-converted grant with only its expiry changed (review
# CODE-003). The folder scope, ID and timestamp are kept exactly as shown, and
# the filesystem is not consulted again. Returns Error and Record.
function Set-GrantExpiry($record, [string]$choice) {
    $result = New-Ordered
    $result['Error'] = $null
    $result['Record'] = $null
    $now = [DateTime]::new([Rules]::TimestampTicks([string]$record['ts'], $true), [DateTimeKind]::Utc)
    $resolved = Resolve-Expiry $choice $now
    if ($null -ne $resolved['Error']) { $result['Error'] = $resolved['Error']; return ,$result }
    $copy = New-Ordered
    foreach ($key in $record.Keys) { $copy[$key] = $record[$key] }
    $copy['expires'] = $resolved['Value']
    $result['Record'] = $copy
    return ,$result
}

# The clipboard text, in a function of its own so tests can supply it.
function Get-ClipboardRequestText {
    return [System.Windows.Forms.Clipboard]::GetText()
}

function Format-Span([long]$minutes) {
    if ($minutes -gt 0 -and $minutes % 1440 -eq 0) { $n = $minutes / 1440; $unit = 'day' }
    elseif ($minutes -gt 0 -and $minutes % 60 -eq 0) { $n = $minutes / 60; $unit = 'hour' }
    else { $n = $minutes; $unit = 'minute' }
    if ($n -ne 1) { $unit += 's' }
    return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0} {1}', $n, $unit)
}

# The confirmation text (design 6.4), built only from the record's fields.
# Lines are joined with LF; the dialog converts them for display.
function Get-Description($record) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $tool = [string]$record['tool']
    if ($tool.Length -eq 0) { $lines.Add('Allow these exact commands (the host sends no tool name):') }
    else { $lines.Add("Allow these exact commands (through tool '" + (Format-VisibleText $tool) + "'):") }
    foreach ($command in $record['commands']) {
        $lines.Add('')
        foreach ($part in ([Visible]::Format([string]$command)).Split([char]0x0A)) { $lines.Add('    ' + $part) }
    }
    $lines.Add('')
    if ($tool -ceq 'shell') { $lines.Add("This host doesn't say which shell runs the command.") }
    $where = [string]$record['where']
    if ($where -ceq 'any') { $lines.Add('Starting in: any folder') }
    elseif ($where -ceq 'dir') { $lines.Add('Starting in: exactly the folder ' + $record['path']) }
    else { $lines.Add('Starting in: any folder of the git repo at ' + $record['path']) }
    $lines.Add('For user: ' + (Format-VisibleText ([string]$record['user_display'])) + ' (' + $record['user'] + ')')
    if ($null -eq $record['hosts']) { $lines.Add('On AI hosts: all') }
    else { $lines.Add('On AI hosts: ' + [string]::Join(', ', [string[]]@($record['hosts']))) }
    if ($null -eq $record['expires']) {
        $lines.Add('Until revoked (no expiry). This is an indefinite permission.')
    } else {
        $ts = [Rules]::TimestampTicks([string]$record['ts'], $true)
        $until = [Rules]::TimestampTicks([string]$record['expires'], $true)
        $local = [DateTime]::new($until, [DateTimeKind]::Utc).ToLocalTime()
        $span = Format-Span ([long](($until - $ts) / [TimeSpan]::TicksPerMinute))
        $lines.Add('Until: ' + $local.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) +
                   ' local time (' + $span + ')')
    }
    $lines.Add('Name: ' + $record['name'])
    $lines.Add('')
    $lines.Add("--- AI's stated reason (not checked) ---")
    $why = [string]$record['why']
    if ($why.Length -eq 0) { $lines.Add('(none given)') } else { $lines.Add((Format-VisibleText $why)) }
    return [string]::Join([string][char]0x0A, $lines)
}

function Format-VisibleText([string]$s) { return [Visible]::Format($s) }

# ==========================================================================
# Writing
# ==========================================================================

$script:FileSddl = 'O:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)'

function Set-ProtectedFileSecurity([string]$path) {
    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm($script:FileSddl)
    [System.IO.File]::SetAccessControl($path, $security)
}

function Test-BytesEqual([byte[]]$a, [byte[]]$b) {
    if ($null -eq $a -or $null -eq $b -or $a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { return $false } }
    return $true
}

# Design 6.1 step 5. Returns an exit code; never retries.
function Write-GrantsAtomically([string]$grantsPath, [byte[]]$oldBytes, [byte[]]$newBytes) {
    $folder = [System.IO.Path]::GetDirectoryName($grantsPath)
    $temp = [System.IO.Path]::Combine($folder, 'grants.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [System.IO.File]::WriteAllBytes($temp, $newBytes)
        $stream = [System.IO.FileStream]::new($temp, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
        try { $stream.Flush($true) } finally { $stream.Dispose() }
        Set-ProtectedFileSecurity $temp
        [System.IO.File]::Replace($temp, $grantsPath, $null)
    } catch {
        $reason = $_.Exception.Message
        try { if ([System.IO.File]::Exists($temp)) { [System.IO.File]::Delete($temp) } } catch { }
        try { $now = [System.IO.File]::ReadAllBytes($grantsPath) } catch { $now = $null }
        if (Test-BytesEqual $now $oldBytes) {
            return (Show-Result 50 ("The write failed and the grants file is unchanged.`n" + $reason))
        }
        if (Test-BytesEqual $now $newBytes) {
            return (Show-Result 51 ("The write reported an error, but the grants file contains the new content.`n" + $reason))
        }
        return (Show-Result 52 ("The write failed and the outcome is unknown. Run: aiallow check, then aiallow list.`n" + $reason))
    }
    $problems = Test-StoreIntegrity $grantsPath $null
    if ($problems.Count -gt 0) {
        return (Show-Result 30 ("Written, but permissions are wrong: " + $problems[0] + "`nRun: aiallow setup"))
    }
    return 0
}

# ==========================================================================
# Dialogs (Windows Forms)
# ==========================================================================

function Show-Result([int]$code, [string]$message) {
    # aiallow launches the writer through UAC with its own console, so output is
    # never redirected there. When it is (automated tests), print the result
    # instead of blocking on a message box. This only changes how a result is
    # shown; confirmations always use a dialog.
    if ([Console]::IsOutputRedirected -or [Console]::IsErrorRedirected) {
        [Console]::Out.WriteLine('result ' + $code + ': ' + $message)
        return $code
    }
    $icon = [System.Windows.Forms.MessageBoxIcon]::Information
    if ($code -ne 0) { $icon = [System.Windows.Forms.MessageBoxIcon]::Warning }
    [void][System.Windows.Forms.MessageBox]::Show($message, 'aiallow', [System.Windows.Forms.MessageBoxButtons]::OK, $icon)
    return $code
}

function New-TextBox([string]$text, [bool]$readOnly) {
    $box = [System.Windows.Forms.TextBox]::new()
    $box.Multiline = $true
    $box.ReadOnly = $readOnly
    $box.WordWrap = $false
    $box.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    $box.Font = [System.Drawing.Font]::new('Consolas', 10)
    $box.Dock = [System.Windows.Forms.DockStyle]::Fill
    $box.Text = $text.Replace([string][char]0x0A, [string][char]0x0D + [char]0x0A)
    return $box
}

function ConvertTo-DialogText([string]$text) {
    return $text.Replace([string][char]0x0A, [string][char]0x0D + [char]0x0A)
}

# The add dialog's text for another expiry choice. $context['candidate'] is the
# grant converted once when the dialog opened (see Invoke-Add); only its expiry
# changes here.
function Get-ExpiryDescription($context, [string]$choice) {
    $again = Set-GrantExpiry $context['candidate'] $choice
    if ($null -ne $again['Error']) { return 'Invalid expiry: ' + $again['Error'].Describe() }
    return (Get-Description $again['Record'])
}

# Shows text and Approve/Cancel. Enter and Esc both cancel; only a click (or
# Tab plus Space) approves. With an $expiryContext, an expiry box is shown and
# changing it regenerates the text. Returns the chosen expiry ('' when there is
# no expiry box), or $null when cancelled.
#
# Event handlers below are plain script blocks. PowerShell runs them in a child
# scope of whatever is executing when the event fires, which is this function
# (inside ShowDialog), so they can see $box, $combo and $expiryContext.
function Show-Confirm([string]$title, [string]$header, [string]$text, $expiryContext) {
    $form = [System.Windows.Forms.Form]::new()
    $form.Text = $title
    $form.Width = 900
    $form.Height = 640
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.TopMost = $true
    $box = New-TextBox $text $true
    $top = [System.Windows.Forms.Label]::new()
    $top.Text = $header
    $top.Dock = [System.Windows.Forms.DockStyle]::Top
    $top.Height = 40
    $panel = [System.Windows.Forms.FlowLayoutPanel]::new()
    $panel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $panel.Height = 40
    $panel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    $cancel = [System.Windows.Forms.Button]::new()
    $cancel.Text = 'Cancel'
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $approve = [System.Windows.Forms.Button]::new()
    $approve.Text = 'Approve'
    $approve.DialogResult = [System.Windows.Forms.DialogResult]::OK
    [void]$panel.Controls.Add($cancel)
    [void]$panel.Controls.Add($approve)
    $combo = $null
    if ($null -ne $expiryContext) {
        $label = [System.Windows.Forms.Label]::new()
        $label.Text = 'Expires:'
        $label.AutoSize = $true
        $combo = [System.Windows.Forms.ComboBox]::new()
        $combo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        foreach ($choice in $expiryContext['choices']) { [void]$combo.Items.Add($choice) }
        $combo.SelectedItem = $expiryContext['initial']
        $combo.add_SelectedIndexChanged({
            $box.Text = ConvertTo-DialogText (Get-ExpiryDescription $expiryContext ([string]$combo.SelectedItem))
        })
        [void]$panel.Controls.Add($combo)
        [void]$panel.Controls.Add($label)
    }
    [void]$form.Controls.Add($box)
    [void]$form.Controls.Add($top)
    [void]$form.Controls.Add($panel)
    $form.AcceptButton = $cancel
    $form.CancelButton = $cancel
    $form.add_Shown({ [void]$cancel.Focus() })
    $result = $form.ShowDialog()
    $chosen = ''
    if ($null -ne $combo) { $chosen = [string]$combo.SelectedItem }
    $form.Dispose()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) { return $chosen }
    return $null
}

# Save-button check for the repair editor: $null when valid, else the error.
function Get-EditError([string]$candidate) {
    $normalized = Get-NormalizedEditText $candidate
    $check = [Rules]::File([System.Text.UTF8Encoding]::new($false).GetBytes($normalized))
    if ($null -ne $check.Error) { return $check.Error.Describe() }
    return $null
}

# The repair editor. Returns the edited text, or $null when cancelled.
function Show-Editor([string]$title, [string]$text) {
    $form = [System.Windows.Forms.Form]::new()
    $form.Text = $title
    $form.Width = 1000
    $form.Height = 700
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.TopMost = $true
    $box = New-TextBox $text $false
    $status = [System.Windows.Forms.Label]::new()
    $status.Dock = [System.Windows.Forms.DockStyle]::Top
    $status.Height = 40
    $status.Text = 'Edit the grants file. Save checks it; nothing invalid is ever saved.'
    $panel = [System.Windows.Forms.FlowLayoutPanel]::new()
    $panel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $panel.Height = 40
    $panel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    $cancel = [System.Windows.Forms.Button]::new()
    $cancel.Text = 'Cancel'
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $save = [System.Windows.Forms.Button]::new()
    $save.Text = 'Save...'
    $state = New-Ordered
    $state['text'] = $null
    $save.add_Click({
        $candidate = $box.Text
        $message = Get-EditError $candidate
        if ($null -eq $message) {
            $state['text'] = $candidate
            $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Close()
        } else {
            $status.Text = 'Not saved: ' + $message
        }
    })
    [void]$panel.Controls.Add($cancel)
    [void]$panel.Controls.Add($save)
    [void]$form.Controls.Add($box)
    [void]$form.Controls.Add($status)
    [void]$form.Controls.Add($panel)
    $form.CancelButton = $cancel
    $result = $form.ShowDialog()
    $form.Dispose()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) { return $state['text'] }
    return $null
}

# ==========================================================================
# Actions
# ==========================================================================

function Resolve-GrantsPath {
    $path = $GrantsPath
    if (-not $path) {
        $path = [System.IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'cc-ai-review', 'grants.jsonl')
    }
    if (-not [Rules]::DrivePathRe.IsMatch($path)) { return $null }
    return $path
}

# Steps shared by add, revoke and edit: integrity, then read the file.
# Returns an exit code (non-zero = stop) and sets $state['bytes'].
function Open-Store([string]$grantsPath, $state) {
    $problems = Test-StoreIntegrity $grantsPath $PSCommandPath
    if ($problems.Count -gt 0) {
        return (Show-Result 30 ("Exception grants are not protected, so nothing was changed:`n" +
                                [string]::Join("`n", $problems.ToArray()) + "`n`nRun: aiallow check"))
    }
    $state['bytes'] = [System.IO.File]::ReadAllBytes($grantsPath)
    return 0
}

function Invoke-Add([string]$grantsPath) {
    $state = New-Ordered
    $code = Open-Store $grantsPath $state
    if ($code -ne 0) { return $code }
    $file = [Rules]::File($state['bytes'])
    if ($null -ne $file.Error) {
        return (Show-Result 21 ('The grants file is invalid (' + $file.Error.Describe() + "). Fix it with: aiallow edit"))
    }
    $text = Get-ClipboardRequestText
    if (-not $text) { return (Show-Result 20 'The clipboard is empty. Copy the request block first.') }
    $now = Get-UtcNow $null
    $request = $null
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text.Trim())
    $e = [Rules]::RequestBytes($bytes, $now.Ticks, [ref]$request)
    if ($null -ne $e) { return (Show-Result 20 ('The request on the clipboard is invalid: ' + $e.Describe())) }
    $nowTicks = $now.Ticks
    foreach ($grant in [Rules]::Active($file.Records, $nowTicks)) {
        if (($grant['user'] -ceq $ForUser) -and ($grant['name'] -ceq $request['name'])) {
            return (Show-Result 20 ("You already have an active grant named '" + $request['name'] + "'. Revoke it first, or use another name."))
        }
    }
    # Convert exactly once: this candidate (folder scope, repo root, ID, time) is
    # what the dialog shows and what gets written. Expiry changes only replace
    # its expiry; the filesystem is never consulted again (review CODE-003).
    $converted = ConvertTo-Grant $request $ForUser $now $file.Records $null
    if ($null -ne $converted['Error']) {
        return (Show-Result 20 ('The request can''t be granted: ' + $converted['Error'].Describe()))
    }
    $candidate = $converted['Record']
    $choices = [System.Collections.Generic.List[string]]::new()
    foreach ($c in @([string]$request['expires'], '15m', '30m', '1h', '2h', '8h', '1d', '7d', 'never')) {
        if (-not $choices.Contains($c)) { $choices.Add($c) }
    }
    $context = New-Ordered
    $context['candidate'] = $candidate
    $context['choices'] = $choices
    $context['initial'] = [string]$request['expires']
    $header = 'Grants file: ' + $grantsPath + '   User: ' + $ForUser
    $chosen = Show-Confirm 'aiallow: approve an exception grant' $header (Get-Description $candidate) $context
    if ($null -eq $chosen) { return (Show-Result 10 'Cancelled. Nothing was changed.') }
    $final = Set-GrantExpiry $candidate $chosen
    if ($null -ne $final['Error']) { return (Show-Result 20 ('Invalid expiry: ' + $final['Error'].Describe())) }
    $line = [JsonOut]::Canonical($final['Record']) + [char]0x0A
    $newBytes = [byte[]]($state['bytes'] + [System.Text.UTF8Encoding]::new($false).GetBytes($line))
    if ($newBytes.Length -gt [Rules]::MaxFileBytes) {
        return (Show-Result 21 'The grants file would exceed 1 MB. Use aiallow setup --reset to start a new one.')
    }
    $code = Write-GrantsAtomically $grantsPath $state['bytes'] $newBytes
    if ($code -ne 0) { return $code }
    return (Show-Result 0 ("Granted '" + $request['name'] + "'. Tell the AI to retry."))
}

function Invoke-Revoke([string]$grantsPath) {
    if (-not $Name -or ($Name -cne '*' -and -not [Rules]::NameRe.IsMatch($Name))) {
        return (Show-Result 20 'Give a grant name to revoke, or * for all of yours.')
    }
    $state = New-Ordered
    $code = Open-Store $grantsPath $state
    if ($code -ne 0) { return $code }
    $file = [Rules]::File($state['bytes'])
    if ($null -ne $file.Error) {
        return (Show-Result 21 ('The grants file is invalid (' + $file.Error.Describe() + "). Fix it with: aiallow edit"))
    }
    $now = Get-UtcNow $null
    $matching = [System.Collections.Generic.List[object]]::new()
    foreach ($grant in [Rules]::Active($file.Records, $now.Ticks)) {
        if (($grant['user'] -ceq $ForUser) -and ($Name -ceq '*' -or $grant['name'] -ceq $Name)) { $matching.Add($grant) }
    }
    if ($matching.Count -eq 0) { return (Show-Result 0 'Nothing to revoke: no active grant of yours matches.') }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($grant in $matching) { $parts.Add((Get-Description $grant)); $parts.Add('') }
    $header = 'Revoke these grants?   Grants file: ' + $grantsPath + '   User: ' + $ForUser
    $chosen = Show-Confirm 'aiallow: revoke' $header ([string]::Join([string][char]0x0A, $parts.ToArray())) $null
    if ($null -eq $chosen) { return (Show-Result 10 'Cancelled. Nothing was changed.') }
    $record = New-Ordered
    $record['v'] = [JsonNumber]::new('1', $true)
    $record['type'] = 'revoke'
    $record['id'] = New-RecordId 'r-' $now (Get-IdSet $file.Records)
    $record['ts'] = Format-StoredTime $now
    $record['user'] = $ForUser
    $record['name'] = $Name
    $line = [JsonOut]::Canonical($record) + [char]0x0A
    $newBytes = [byte[]]($state['bytes'] + [System.Text.UTF8Encoding]::new($false).GetBytes($line))
    if ($newBytes.Length -gt [Rules]::MaxFileBytes) {
        return (Show-Result 21 'The grants file would exceed 1 MB. Use aiallow setup --reset to start a new one.')
    }
    $code = Write-GrantsAtomically $grantsPath $state['bytes'] $newBytes
    if ($code -ne 0) { return $code }
    return (Show-Result 0 ('Revoked ' + $matching.Count + ' grant(s).'))
}

function Invoke-Edit([string]$grantsPath) {
    $problems = Test-StoreIntegrity $grantsPath $PSCommandPath
    if ($problems.Count -gt 0) {
        return (Show-Result 30 ("Exception grants are not protected, so nothing was changed:`n" +
                                [string]::Join("`n", $problems.ToArray()) + "`n`nRun: aiallow check"))
    }
    $oldBytes = [System.IO.File]::ReadAllBytes($grantsPath)
    if ($oldBytes.Length -gt [Rules]::MaxFileBytes) {
        return (Show-Result 21 'The grants file is over 1 MB. Use aiallow setup --reset, which keeps the old folder as a backup.')
    }
    # Lenient decoding for display only: the current contents may be invalid.
    $oldText = [System.Text.UTF8Encoding]::new($false, $false).GetString($oldBytes)
    $editorText = $oldText
    while ($true) {
        $edited = Show-Editor 'aiallow: repair the grants file' $editorText
        if ($null -eq $edited) { return (Show-Result 10 'Cancelled. Nothing was changed.') }
        $normalized = Get-NormalizedEditText $edited
        $diff = [LineDiff]::Compute((Split-Lines $oldText), (Split-Lines $normalized))
        $header = 'Every removed (-) and added (+) line. Grants file: ' + $grantsPath
        $chosen = Show-Confirm 'aiallow: confirm the repair' $header ([string]::Join([string][char]0x0A, $diff.Lines.ToArray())) $null
        if ($null -ne $chosen) { break }
        $editorText = $edited   # back to the editor with the user's edits; the diff stays against the original
    }
    $newBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($normalized)
    $code = Write-GrantsAtomically $grantsPath $oldBytes $newBytes
    if ($code -ne 0) { return $code }
    return (Show-Result 0 'The grants file was repaired.')
}

# D15: text boxes use CRLF. Commands store CR only as the escape \r.
function Get-NormalizedEditText([string]$text) {
    $t = $text.Replace([string][char]0x0D + [char]0x0A, [string][char]0x0A)
    if ($t.Length -gt 0 -and $t[$t.Length - 1] -ne [char]0x0A) { $t += [char]0x0A }
    return $t
}

function Split-Lines([string]$text) {
    $t = $text.Replace([string][char]0x0D + [char]0x0A, [string][char]0x0A)
    if ($t.Length -eq 0) { return ,[string[]]@() }
    if ($t[$t.Length - 1] -eq [char]0x0A) { $t = $t.Substring(0, $t.Length - 1) }
    return ,$t.Split([char]0x0A)
}

function Invoke-Main {
    $grantsPath = Resolve-GrantsPath
    if ($null -eq $grantsPath) { return (Show-Result 30 'The grants path must start with a drive letter.') }
    if (-not [Rules]::IsValidSid($ForUser)) { return (Show-Result 20 'The -ForUser value is not a valid SID.') }
    $mutex = $null
    $owned = $false
    try {
        try {
            $created = $false
            $mutex = [System.Threading.Mutex]::new($false, 'Global\cc-ai-review-grants', [ref]$created)
        } catch [System.UnauthorizedAccessException] {
            return (Show-Result 41 'The grant lock exists but access to it is denied. Nothing was changed.')
        } catch [System.Threading.WaitHandleCannotBeOpenedException] {
            return (Show-Result 41 'The grant lock name is used by another kind of object. Nothing was changed.')
        }
        try { $owned = $mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $owned = $true }   # previous holder crashed
        if (-not $owned) { return (Show-Result 40 'Another grant window is open. Nothing was changed.') }

        if ($Action -ceq 'add') { return (Invoke-Add $grantsPath) }
        if ($Action -ceq 'revoke') { return (Invoke-Revoke $grantsPath) }
        if ($Action -ceq 'edit') { return (Invoke-Edit $grantsPath) }
        return (Show-Result 60 'Unknown action.')
    } catch {
        return (Show-Result 60 ('Unexpected error: ' + $_.Exception.Message))
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        if ($null -ne $mutex) { $mutex.Dispose() }
    }
}

# ==========================================================================
# Read-only validate actions (tests and diagnostics). No mutex, no UI.
# ==========================================================================

function Write-Output-Json($value) {
    [Console]::Out.Write([JsonOut]::Ascii($value))
    [Console]::Out.Write([char]0x0A)
}

function ConvertTo-ErrorObject($e, [bool]$withLine) {
    if ($null -eq $e) { return $null }
    $o = New-Ordered
    $o['code'] = $e.Code
    $o['field'] = $e.Field
    if ($withLine) { $o['line'] = $e.Line }
    return ,$o
}

function Invoke-ValidateRequest {
    $now = Get-UtcNow $Now
    $user = $ForUser
    if (-not $user) { $user = 'S-1-5-21-0-0-0-1000' }
    $request = $null
    $e = [Rules]::RequestBytes([System.IO.File]::ReadAllBytes($RequestFile), $now.Ticks, [ref]$request)
    $out = New-Ordered
    $out['valid'] = ($null -eq $e)
    $out['error'] = ConvertTo-ErrorObject $e $true
    $out['conversion_error'] = $null
    $out['record'] = $null
    $out['description'] = $null
    if ($null -eq $e) {
        $converted = ConvertTo-Grant $request $user $now $null $null
        if ($null -ne $converted['Error']) {
            $out['conversion_error'] = ConvertTo-ErrorObject $converted['Error'] $false
        } else {
            $out['record'] = $converted['Record']
            $out['description'] = Get-Description $converted['Record']
        }
    }
    Write-Output-Json $out
    return 0
}

function Invoke-ValidateFile {
    $now = Get-UtcNow $Now
    $file = [Rules]::File([System.IO.File]::ReadAllBytes($GrantsFile))
    $out = New-Ordered
    $out['valid'] = ($null -eq $file.Error)
    $out['error'] = ConvertTo-ErrorObject $file.Error $true
    $active = New-Ordered
    if ($null -eq $file.Error) {
        foreach ($grant in [Rules]::Active($file.Records, $now.Ticks)) {
            $user = [string]$grant['user']
            if (-not $active.Contains($user)) { $active[$user] = [System.Collections.Generic.List[object]]::new() }
            $active[$user].Add([string]$grant['id'])
        }
    }
    $out['active'] = $active
    Write-Output-Json $out
    return 0
}

function Invoke-ValidateAcl {
    $parser = [JsonParser]::new([System.IO.File]::ReadAllText($AclFile))
    $cases = $parser.ParseDocument()
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($case in $cases) {
        $hex = [string]$case['hex']
        $bytes = [byte[]]::new($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        $problems = [Security]::Evaluate($bytes, [bool]$case['reparse'], [string]$case['role'], 'fixture')
        $o = New-Ordered
        $o['id'] = $case['id']
        $o['ok'] = ($problems.Count -eq 0)
        $o['problem'] = $null
        if ($problems.Count -gt 0) { $o['problem'] = $problems[0][0] }
        $results.Add($o)
    }
    Write-Output-Json $results
    return 0
}

function Invoke-ValidateDiff {
    $old = Split-Lines ([System.IO.File]::ReadAllText($OldFile))
    $new = Split-Lines ([System.IO.File]::ReadAllText($NewFile))
    $diff = [LineDiff]::Compute($old, $new)
    $out = New-Ordered
    $out['path'] = $diff.Path
    $out['lines'] = $diff.Lines
    Write-Output-Json $out
    return 0
}

# Test helper: parse a JSON file and print it back (array-shape round trip).
function Invoke-ValidateRoundTrip {
    $value = $null
    $e = [Rules]::ParseLine([System.IO.File]::ReadAllText($RequestFile), [ref]$value)
    if ($null -ne $e) { Write-Output-Json (ConvertTo-ErrorObject $e $false); return 0 }
    $out = New-Ordered
    $out['canonical'] = [JsonOut]::Canonical($value)
    $out['value'] = $value
    Write-Output-Json $out
    return 0
}

# ==========================================================================
# Entry point
# ==========================================================================

# Setup dot-sources this file with -LibraryOnly to reuse the helpers above.
# This must stay after the last definition and before any action runs.
if ($LibraryOnly) { return }

if ($Action -ceq 'validate-request') { exit (Invoke-ValidateRequest) }
if ($Action -ceq 'validate-file') { exit (Invoke-ValidateFile) }
if ($Action -ceq 'validate-acl') { exit (Invoke-ValidateAcl) }
if ($Action -ceq 'validate-diff') { exit (Invoke-ValidateDiff) }
if ($Action -ceq 'validate-roundtrip') { exit (Invoke-ValidateRoundTrip) }

exit (Invoke-Main)
